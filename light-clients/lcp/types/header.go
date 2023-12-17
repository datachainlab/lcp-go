package types

import (
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientMessage = (*UpdateClientMessage)(nil)

func (UpdateClientMessage) ClientType() string {
	return ClientTypeLCP
}

func (ucm UpdateClientMessage) GetHeight() exported.Height {
	m, err := ucm.GetELCMessage()
	if err != nil {
		panic(err)
	}
	return m.PostHeight
}

func (ucm UpdateClientMessage) ValidateBasic() error {
	if _, err := ucm.GetELCMessage(); err != nil {
		return err
	}
	return nil
}

func (ucm UpdateClientMessage) GetELCMessage() (*ELCUpdateClientMessage, error) {
	m, err := EthABIDecodeHeaderedMessage(ucm.ElcMessage)
	if err != nil {
		return nil, err
	}
	return m.GetUpdateClientMessage()
}

var _ exported.ClientMessage = (*RegisterEnclaveKeyMessage)(nil)

func (RegisterEnclaveKeyMessage) ClientType() string {
	return ClientTypeLCP
}

func (RegisterEnclaveKeyMessage) GetHeight() exported.Height {
	// XXX: the header doesn't have height info, so return zero
	// this is just workaround until this function removed
	return clienttypes.ZeroHeight()
}

func (RegisterEnclaveKeyMessage) ValidateBasic() error {
	return nil
}
