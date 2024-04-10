package types

import (
	"fmt"

	"github.com/cosmos/ibc-go/v8/modules/core/exported"
)

type ProxyMessage interface{}

var _ exported.ClientMessage = (*UpdateClientMessage)(nil)

func (UpdateClientMessage) ClientType() string {
	return ClientTypeLCP
}

func (ucm UpdateClientMessage) GetHeight() exported.Height {
	m, err := ucm.GetProxyMessage()
	if err != nil {
		panic(err)
	}
	switch m := m.(type) {
	case *UpdateStateProxyMessage:
		return m.PostHeight
	default:
		panic(fmt.Errorf("unexpected message type: %T", m))
	}
}

func (ucm UpdateClientMessage) ValidateBasic() error {
	if _, err := ucm.GetProxyMessage(); err != nil {
		return err
	}
	return nil
}

func (ucm UpdateClientMessage) GetProxyMessage() (ProxyMessage, error) {
	m, err := EthABIDecodeHeaderedProxyMessage(ucm.ProxyMessage)
	if err != nil {
		return nil, err
	}
	if m.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, m.Version)
	}
	if m.Type == LCPMessageTypeUpdateState {
		return m.GetUpdateStateProxyMessage()
	} else if m.Type == LCPMessageTypeMisbehaviour {
		return m.GetMisbehaviourProxyMessage()
	} else {
		return nil, fmt.Errorf("unexpected message type: %v", m.Type)
	}
}

var _ exported.ClientMessage = (*RegisterEnclaveKeyMessage)(nil)

func (RegisterEnclaveKeyMessage) ClientType() string {
	return ClientTypeLCP
}

func (RegisterEnclaveKeyMessage) ValidateBasic() error {
	return nil
}
