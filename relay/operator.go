package relay

import (
	"encoding/hex"
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/hyperledger-labs/yui-relayer/core"
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

func (pr *Prover) GetOperatorsThreshold() Fraction {
	if pr.config.OperatorsThreshold.Denominator == 0 && pr.config.OperatorsThreshold.Numerator == 0 {
		return Fraction{Numerator: 1, Denominator: 1}
	}
	return pr.config.OperatorsThreshold
}

func (pr *Prover) updateOperators(verifier core.Chain, nonce uint64, newOperators []common.Address, threshold Fraction) error {
	if nonce == 0 {
		return fmt.Errorf("invalid nonce: %v", nonce)
	}
	if threshold.Numerator == 0 || threshold.Denominator == 0 {
		return fmt.Errorf("invalid threshold: %v", threshold)
	}
	commitment, err := pr.ComputeEIP712UpdateOperatorsHash(
		nonce,
		newOperators,
		threshold.Numerator,
		threshold.Denominator,
	)
	if err != nil {
		return err
	}
	sig, err := pr.OperatorSign(commitment)
	if err != nil {
		return err
	}
	var ops [][]byte
	for _, operator := range newOperators {
		ops = append(ops, operator.Bytes())
	}
	message := &lcptypes.UpdateOperatorsMessage{
		Nonce:                            nonce,
		NewOperators:                     ops,
		NewOperatorsThresholdNumerator:   threshold.Numerator,
		NewOperatorsThresholdDenominator: threshold.Denominator,
		Signatures:                       [][]byte{sig},
	}
	signer, err := verifier.GetAddress()
	if err != nil {
		return err
	}
	msg, err := clienttypes.NewMsgUpdateClient(verifier.Path().ClientID, message, signer.String())
	if err != nil {
		return err
	}
	if _, err := verifier.SendMsgs([]sdk.Msg{msg}); err != nil {
		return err
	}
	return nil
}
