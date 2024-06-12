package types

import (
	"bytes"
	"fmt"
	"time"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/sgx/ias"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func (cs ClientState) VerifyClientMessage(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, clientMsg exported.ClientMessage) error {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err)
		}
		if err := cs.VerifyOperatorProofs(ctx, clientStore, crypto.Keccak256Hash(clientMsg.ProxyMessage), clientMsg.Signatures); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, err.Error())
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.verifyUpdateClient(ctx, cdc, clientStore, clientMsg, pmsg)
		case *MisbehaviourProxyMessage:
			return cs.verifyMisbehaviour(ctx, cdc, clientStore, clientMsg, pmsg)
		default:
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg)
		}
	case *RegisterEnclaveKeyMessage:
		return cs.verifyRegisterEnclaveKey(ctx, clientStore, clientMsg)
	default:
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg)
	}
}

func (cs ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg exported.ClientMessage) {
	cs.Frozen = true
	clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, &cs))
}

func (cs ClientState) verifyUpdateClient(ctx sdk.Context, cdc codec.BinaryCodec, store storetypes.KVStore, msg *UpdateClientMessage, pmsg *UpdateStateProxyMessage) error {
	if cs.LatestHeight.IsZero() {
		if len(pmsg.EmittedStates) == 0 {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `NewState` must be non-nil", msg)
		}
	} else {
		if pmsg.PrevHeight == nil || pmsg.PrevStateID == nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `PrevHeight` and `PrevStateID` must be non-nil", msg)
		}
		prevConsensusState, err := GetConsensusState(store, cdc, pmsg.PrevHeight)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get consensus state: %v", err)
		}
		if !bytes.Equal(prevConsensusState.StateId, pmsg.PrevStateID[:]) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected StateID: expected=%v actual=%v", prevConsensusState.StateId, pmsg.PrevStateID[:])
		}
	}

	if err := pmsg.Context.Validate(ctx.BlockTime()); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid context: %v", err)
	}

	return nil
}

func (cs ClientState) verifyRegisterEnclaveKey(ctx sdk.Context, store storetypes.KVStore, message *RegisterEnclaveKeyMessage) error {
	// TODO define error types

	if err := ias.VerifyReport(message.Report, message.Signature, message.SigningCert, ctx.BlockTime()); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: message=%v, err=%v", message, err)
	}
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err)
	}
	quoteStatus := avr.ISVEnclaveQuoteStatus.String()
	if quoteStatus == QuoteOK {
		if len(avr.AdvisoryIDs) != 0 {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "advisory IDs should be empty when status is OK: actual=%v", avr.AdvisoryIDs)
		}
	} else {
		if !cs.isAllowedStatus(quoteStatus) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed quote status exists: allowed=%v actual=%v", cs.AllowedQuoteStatuses, quoteStatus)
		}
		if !cs.isAllowedAdvisoryIDs(avr.AdvisoryIDs) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed advisory ID(s) exists: allowed=%v actual=%v", cs.AllowedAdvisoryIds, avr.AdvisoryIDs)
		}
	}
	quote, err := avr.Quote()
	if err != nil {
		return err
	}
	if !bytes.Equal(cs.Mrenclave, quote.Report.MRENCLAVE[:]) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: mrenclave mismatch: expected=%v actual=%v", cs.Mrenclave, quote.Report.MRENCLAVE[:])
	}
	var operator common.Address
	if len(message.OperatorSignature) > 0 {
		commitment, err := ComputeEIP712RegisterEnclaveKeyHash(ctx.ChainID(), []byte(exported.StoreKey), message.Report)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute commitment: %v", err)
		}
		operator, err = RecoverAddress(commitment, message.OperatorSignature)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: %v", err)
		}
	}
	ek, expectedOperator, err := ias.GetEKAndOperator(quote)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get enclave key and operator: %v", err)
	}
	if (expectedOperator != common.Address{}) && operator != expectedOperator {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid operator: expected=%v actual=%v", expectedOperator, operator)
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if cs.Contains(store, ek) {
		if err := cs.ensureEKInfoMatch(store, ek, operator, expiredAt); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid enclave key info: %v", err)
		}
	}
	return nil
}

func (cs ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err))
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.updateClient(cdc, clientStore, pmsg)
		default:
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg))
		}
	case *RegisterEnclaveKeyMessage:
		return cs.registerEnclaveKey(ctx, clientStore, clientMsg)
	default:
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg))
	}
}

func (cs ClientState) updateClient(cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg *UpdateStateProxyMessage) []exported.Height {
	if cs.LatestHeight.LT(msg.PostHeight) {
		cs.LatestHeight = msg.PostHeight
	}
	consensusState := ConsensusState{StateId: msg.PostStateID[:], Timestamp: msg.Timestamp.Uint64()}

	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, &consensusState, msg.PostHeight)
	return nil
}

func (cs ClientState) registerEnclaveKey(ctx sdk.Context, clientStore storetypes.KVStore, message *RegisterEnclaveKeyMessage) []exported.Height {
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err))
	}
	quote, err := avr.Quote()
	if err != nil {
		panic(err)
	}
	ek, operator, err := ias.GetEKAndOperator(quote)
	if err != nil {
		panic(err)
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if cs.Contains(clientStore, ek) {
		if err := cs.ensureEKInfoMatch(clientStore, ek, operator, expiredAt); err != nil {
			panic(err)
		}
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				EventTypeRegisteredEnclaveKey,
				sdk.NewAttribute(AttributeKeyEnclaveKey, ek.Hex()),
				sdk.NewAttribute(AttributeExpiredAt, expiredAt.String()),
			),
		)
		return nil
	}
	if err := cs.SetEKInfo(clientStore, ek, operator, expiredAt); err != nil {
		panic(err)
	}
	return nil
}

func (cs ClientState) Contains(clientStore storetypes.KVStore, ek common.Address) bool {
	return clientStore.Has(enclaveKeyPath(ek))
}

func (cs ClientState) GetEKInfo(clientStore storetypes.KVStore, ek common.Address) (*EKInfo, error) {
	if !cs.Contains(clientStore, ek) {
		return nil, nil
	}
	bz := clientStore.Get(enclaveKeyPath(ek))
	if len(bz) != (8 + 20) {
		return nil, fmt.Errorf("invalid enclave key info: expected=%v actual=%v", 8+20, len(bz))
	}
	return &EKInfo{
		ExpiredAt: sdk.BigEndianToUint64(bz[:8]),
		Operator:  common.BytesToAddress(bz[8:]),
	}, nil
}

func (cs ClientState) ensureEKInfoMatch(clientStore storetypes.KVStore, ek common.Address, operator common.Address, expiredAt time.Time) error {
	ekInfo, err := cs.GetEKInfo(clientStore, ek)
	if err != nil {
		return err
	}
	if ekInfo == nil {
		return fmt.Errorf("enclave key '%v' not found", ek)
	}
	if ekInfo.Operator != operator {
		return fmt.Errorf("enclave key '%v' operator mismatch: expected=%v actual=%v", ek, operator, ekInfo.Operator)
	}
	if ekInfo.ExpiredAt != uint64(expiredAt.Unix()) {
		return fmt.Errorf("enclave key '%v' expiredAt mismatch: expected=%v actual=%v", ek, expiredAt, time.Unix(int64(ekInfo.ExpiredAt), 0))
	}
	return nil
}

func (cs ClientState) SetEKInfo(clientStore storetypes.KVStore, ek, operator common.Address, expiredAt time.Time) error {
	clientStore.Set(enclaveKeyPath(ek), append(sdk.Uint64ToBigEndian(uint64(expiredAt.Unix())), operator.Bytes()...))
	return nil
}

type EKInfo struct {
	ExpiredAt uint64
	Operator  common.Address
}

func (cs ClientState) IsActiveKey(blockTime time.Time, clientStore storetypes.KVStore, ek common.Address) (bool, error) {
	ekInfo, err := cs.GetEKInfo(clientStore, ek)
	if err != nil {
		return false, err
	}
	if ekInfo == nil {
		return false, nil
	}
	return time.Unix(int64(ekInfo.ExpiredAt), 0).After(blockTime), nil
}

func (cs ClientState) IsActiveKeyOperator(blockTime time.Time, clientStore storetypes.KVStore, ek, operator common.Address) (bool, error) {
	ekInfo, err := cs.GetEKInfo(clientStore, ek)
	if err != nil {
		return false, err
	}
	if ekInfo == nil {
		return false, nil
	}
	return ekInfo.Operator == operator && time.Unix(int64(ekInfo.ExpiredAt), 0).After(blockTime), nil
}

func (cs ClientState) VerifyOperatorProofs(ctx sdk.Context, clientStore storetypes.KVStore, commitment [32]byte, signatures [][]byte) error {
	operators := cs.GetOperators()
	sigNum := len(signatures)
	opNum := len(operators)
	if opNum == 0 {
		if sigNum != 1 {
			return fmt.Errorf("invalid signature length: expected=%v actual=%v", 1, sigNum)
		}
		ek, err := RecoverAddress(commitment, signatures[0])
		if err != nil {
			return err
		}
		active, err := cs.IsActiveKey(ctx.BlockTime(), clientStore, ek)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("enclave key '%v' is not active", ek)
		}
		return nil
	} else if opNum != sigNum {
		return fmt.Errorf("invalid signature length: expected=%v actual=%v", opNum, sigNum)
	}

	var success uint64 = 0
	for i, op := range operators {
		if len(signatures[i]) == 0 {
			continue
		}
		ek, err := RecoverAddress(commitment, signatures[i])
		if err != nil {
			return err
		}
		active, err := cs.IsActiveKeyOperator(ctx.BlockTime(), clientStore, ek, op)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("enclave key '%v' is not active", ek)
		}
		success++
	}

	if success*cs.OperatorsThresholdDenominator < cs.OperatorsThresholdDenominator*uint64(opNum) {
		return fmt.Errorf("insufficient signatures: expected=%v actual=%v", cs.OperatorsThresholdDenominator, success)
	}

	return nil
}

func (cs ClientState) GetOperators() []common.Address {
	var operators []common.Address
	for _, op := range cs.Operators {
		operators = append(operators, common.BytesToAddress(op))
	}
	return operators
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
