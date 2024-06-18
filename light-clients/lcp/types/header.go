package types

import (
	"fmt"

	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
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

var _ exported.ClientMessage = (*UpdateOperatorsMessage)(nil)

func (UpdateOperatorsMessage) ClientType() string {
	return ClientTypeLCP
}

func (m UpdateOperatorsMessage) GetNewOperators() ([]common.Address, error) {
	ops := make([]common.Address, len(m.NewOperators))
	for i, op := range m.NewOperators {
		if len(op) != 20 {
			return nil, fmt.Errorf("invalid operator address length: expected=%v actual=%v", 20, len(op))
		}
		ops[i] = common.BytesToAddress(op)
	}
	return ops, nil
}

func (m UpdateOperatorsMessage) ValidateBasic() error {
	if m.NewOperatorsThresholdNumerator == 0 {
		return fmt.Errorf("new operators threshold numerator cannot be zero")
	}
	if m.NewOperatorsThresholdDenominator == 0 {
		return fmt.Errorf("new operators threshold denominator cannot be zero")
	}
	if m.NewOperatorsThresholdNumerator > m.NewOperatorsThresholdDenominator {
		return fmt.Errorf("new operators threshold numerator cannot be greater than denominator")
	}
	if len(m.Signatures) == 0 {
		return fmt.Errorf("signatures cannot be empty")
	}
	return nil
}
