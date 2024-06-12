package types

import (
	"bytes"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
)

func (cs ClientState) CheckForMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg exported.ClientMessage) bool {
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

func (cs ClientState) verifyMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg *UpdateClientMessage, pmsg *MisbehaviourProxyMessage) error {
	for _, state := range pmsg.PrevStates {
		cons, err := GetConsensusState(clientStore, cdc, state.Height)
		if err != nil {
			return err
		}
		if !bytes.Equal(cons.StateId, state.StateID[:]) {
			return errorsmod.Wrapf(ErrInvalidMisbehaviour, "unexpected StateID: expected=%v actual=%v", cons.StateId, state.StateID)
		}
	}
	if err := pmsg.Context.Validate(ctx.BlockTime()); err != nil {
		return errorsmod.Wrapf(ErrInvalidMisbehaviour, "invalid context: %v", err)
	}
	return nil
}
