package relay

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func (pr *Prover) OperatorSign(commitment [32]byte) ([]byte, error) {
	privKey, err := pr.getOperatorPrivateKey()
	if err != nil {
		return nil, err
	}
	return secp256k1.Sign(commitment[:], privKey)
}

func (pr *Prover) getOperatorPrivateKey() ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(pr.config.OperatorPrivateKey, "0x"))
}

func (pr *Prover) IsOperatorEnabled() bool {
	return len(pr.config.OperatorPrivateKey) > 0
}

func (pr *Prover) GetOperators() ([]common.Address, error) {
	var operators []common.Address
	for _, operator := range pr.config.Operators {
		addrStr := strings.TrimPrefix(operator, "0x")
		if len(addrStr) != 40 {
			return nil, fmt.Errorf("invalid operator address length %v", len(addrStr))
		}
		addr := common.HexToAddress(operator)
		operators = append(operators, addr)
	}
	return operators, nil
}
