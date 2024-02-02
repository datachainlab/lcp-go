package types

import (
	"bytes"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/datachainlab/lcp-go/sgx/ias"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
)

func (cs ClientState) VerifyClientMessage(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) error {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err)
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.verifyUpdateClient(ctx, cdc, clientStore, clientMsg, pmsg)
		case *MisbehaviourProxyMessage:
			return cs.verifyMisbehaviour(ctx, cdc, clientStore, clientMsg, pmsg)
		default:
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg)
		}
	case *RegisterEnclaveKeyMessage:
		return cs.verifyRegisterEnclaveKey(ctx, cdc, clientStore, clientMsg)
	default:
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg)
	}
}

func (cs ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, msg exported.ClientMessage) {
	cs.Frozen = true
	clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, &cs))
}

func (cs ClientState) verifyUpdateClient(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, msg *UpdateClientMessage, pmsg *UpdateStateProxyMessage) error {
	if cs.LatestHeight.IsZero() {
		if len(pmsg.EmittedStates) == 0 {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `NewState` must be non-nil", msg)
		}
	} else {
		if pmsg.PrevHeight == nil || pmsg.PrevStateID == nil {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `PrevHeight` and `PrevStateID` must be non-nil", msg)
		}
		prevConsensusState, err := GetConsensusState(store, cdc, pmsg.PrevHeight)
		if err != nil {
			return err
		}
		if !bytes.Equal(prevConsensusState.StateId, pmsg.PrevStateID[:]) {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "unexpected StateID: expected=%v actual=%v", prevConsensusState.StateId, pmsg.PrevStateID[:])
		}
	}

	signer := common.BytesToAddress(msg.Signer)
	if !cs.IsActiveKey(ctx.BlockTime(), store, signer) {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "signer '%v' not found", signer)
	}

	if err := VerifySignatureWithSignBytes(msg.ProxyMessage, msg.Signature, signer); err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, err.Error())
	}

	if err := pmsg.Context.Validate(ctx.BlockTime()); err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid context: %v", err)
	}

	return nil
}

func (cs ClientState) verifyRegisterEnclaveKey(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, message *RegisterEnclaveKeyMessage) error {
	// TODO define error types

	if err := ias.VerifyReport(message.Report, message.Signature, message.SigningCert, ctx.BlockTime()); err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: message=%v, err=%v", message, err)
	}
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err)
	}
	quoteStatus := avr.ISVEnclaveQuoteStatus.String()
	if quoteStatus == QuoteOK {
		if len(avr.AdvisoryIDs) != 0 {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "advisory IDs should be empty when status is OK: actual=%v", avr.AdvisoryIDs)
		}
	} else {
		if !cs.isAllowedStatus(quoteStatus) {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "disallowed quote status exists: allowed=%v actual=%v", cs.AllowedQuoteStatuses, quoteStatus)
		}
		if !cs.isAllowedAdvisoryIDs(avr.AdvisoryIDs) {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "disallowed advisory ID(s) exists: allowed=%v actual=%v", cs.AllowedAdvisoryIds, avr.AdvisoryIDs)
		}
	}
	quote, err := avr.Quote()
	if err != nil {
		return err
	}
	if !bytes.Equal(cs.Mrenclave, quote.Report.MRENCLAVE[:]) {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: mrenclave mismatch: expected=%v actual=%v", cs.Mrenclave, quote.Report.MRENCLAVE[:])
	}
	addr, err := ias.GetEnclaveKeyAddress(quote)
	if err != nil {
		return err
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if e, found := cs.GetEnclaveKeyExpiredAt(store, addr); found {
		if !e.Equal(expiredAt) {
			return sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "enclave key '%v' already exists: expected=%v actual=%v", addr, e, expiredAt)
		}
	}
	return nil
}

func (cs ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			panic(sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err))
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.updateClient(ctx, cdc, clientStore, pmsg)
		default:
			panic(sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg))
		}
	case *RegisterEnclaveKeyMessage:
		return cs.registerEnclaveKey(ctx, cdc, clientStore, clientMsg)
	default:
		panic(sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg))
	}
}

func (cs ClientState) updateClient(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, msg *UpdateStateProxyMessage) []exported.Height {
	if cs.LatestHeight.LT(msg.PostHeight) {
		cs.LatestHeight = msg.PostHeight
	}
	consensusState := ConsensusState{StateId: msg.PostStateID[:], Timestamp: msg.Timestamp.Uint64()}

	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, &consensusState, msg.PostHeight)
	return nil
}

func (cs ClientState) registerEnclaveKey(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, message *RegisterEnclaveKeyMessage) []exported.Height {
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		panic(sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err))
	}
	quote, err := avr.Quote()
	if err != nil {
		panic(err)
	}
	addr, err := ias.GetEnclaveKeyAddress(quote)
	if err != nil {
		panic(err)
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if cs.Contains(clientStore, addr) {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				EventTypeRegisteredEnclaveKey,
				sdk.NewAttribute(AttributeKeyEnclaveKey, addr.Hex()),
				sdk.NewAttribute(AttributeExpiredAt, expiredAt.String()),
			),
		)
		return nil
	}
	cs.AddEnclaveKey(clientStore, addr, expiredAt)
	return nil
}

func (cs ClientState) GetEnclaveKeyExpiredAt(clientStore sdk.KVStore, key common.Address) (time.Time, bool) {
	if !cs.Contains(clientStore, key) {
		return time.Time{}, false
	}
	expiredAt := sdk.BigEndianToUint64(clientStore.Get(enclaveKeyPath(key)))
	return time.Unix(int64(expiredAt), 0), true
}

func (cs ClientState) Contains(clientStore sdk.KVStore, key common.Address) bool {
	return clientStore.Has(enclaveKeyPath(key))
}

func (cs ClientState) IsActiveKey(blockTime time.Time, clientStore sdk.KVStore, key common.Address) bool {
	if !cs.Contains(clientStore, key) {
		return false
	}
	expiredAt := sdk.BigEndianToUint64(clientStore.Get(enclaveKeyPath(key)))
	return time.Unix(int64(expiredAt), 0).After(blockTime)
}

func (cs ClientState) AddEnclaveKey(clientStore sdk.KVStore, key common.Address, expiredAt time.Time) {
	clientStore.Set(enclaveKeyPath(key), sdk.Uint64ToBigEndian(uint64(expiredAt.Unix())))
}

func (cs ClientState) getKeyExpiration() time.Duration {
	return time.Duration(cs.KeyExpiration) * time.Second
}

func (cs ClientState) isAllowedStatus(status string) bool {
	if status == QuoteOK {
		return true
	}
	for _, s := range cs.AllowedQuoteStatuses {
		if status == s {
			return true
		}
	}
	return false
}

func (cs ClientState) isAllowedAdvisoryIDs(advIDs []string) bool {
	if len(advIDs) == 0 {
		return true
	}
	set := mapset.NewThreadUnsafeSet(cs.AllowedAdvisoryIds...)
	return set.Contains(advIDs...)
}

func enclaveKeyPath(key common.Address) []byte {
	return []byte("aux/enclave_keys/" + key.Hex())
}
