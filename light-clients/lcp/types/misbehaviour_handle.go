package types

import (
	"bytes"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
)

func (cs ClientState) CheckForMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, msg exported.ClientMessage) bool {
	switch msg := msg.(type) {
	case *UpdateClientMessage:
		m, err := msg.GetProxyMessage()
		if err != nil {
			return false
		}
		switch m.(type) {
		case *MisbehaviourProxyMessage:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func (cs ClientState) verifyMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, msg *UpdateClientMessage, pmsg *MisbehaviourProxyMessage) error {
	for _, state := range pmsg.PrevStates {
		cons, err := GetConsensusState(clientStore, cdc, state.Height)
		if err != nil {
			return err
		}
		if !bytes.Equal(cons.StateId, state.StateID[:]) {
			return sdkerrors.Wrapf(ErrInvalidMisbehaviour, "unexpected StateID: expected=%v actual=%v", cons.StateId, state.StateID)
		}
	}

	signer := common.BytesToAddress(msg.Signer)
	if !cs.IsActiveKey(ctx.BlockTime(), clientStore, signer) {
		return sdkerrors.Wrapf(ErrInvalidMisbehaviour, "signer '%v' not found", signer)
	}

	if err := VerifySignatureWithSignBytes(msg.ProxyMessage, msg.Signature, signer); err != nil {
		return sdkerrors.Wrapf(ErrInvalidMisbehaviour, err.Error())
	}

	if err := pmsg.Context.Validate(ctx.BlockTime()); err != nil {
		return sdkerrors.Wrapf(ErrInvalidMisbehaviour, "invalid context: %v", err)
	}

	return nil
}
