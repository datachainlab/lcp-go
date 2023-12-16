package types

import (
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientMessage = (*UpdateClientMessage)(nil)

func (UpdateClientMessage) ClientType() string {
	return ClientTypeLCP
}

func (m UpdateClientMessage) GetHeight() exported.Height {
	c, err := m.GetMessage()
	if err != nil {
		panic(err)
	}
	return c.PostHeight
}

func (m UpdateClientMessage) ValidateBasic() error {
	if _, err := m.GetMessage(); err != nil {
		return err
	}
	return nil
}

func (h UpdateClientMessage) GetMessage() (*ELCUpdateClientMessage, error) {
	c, err := EthABIDecodeHeaderedMessage(h.ElcMessage)
	if err != nil {
		return nil, err
	}
	return c.GetUpdateClientMessage()
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
