package relay

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

func (pr *Prover) IsOperatorEnabled() bool {
	return len(pr.config.Operators) > 0
}

func (pr *Prover) GetOperators() ([]common.Address, error) {
	var operators []common.Address
	for i, operator := range pr.config.Operators {
		addr, err := decodeOperatorAddress(operator)
		if err != nil {
			return nil, fmt.Errorf("failed to decode operator address: index=%v, operator=%v %w", i, operator, err)
		}
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

func (pr *Prover) updateOperators(ctx context.Context, counterparty core.Chain, nonce uint64, newOperators []common.Address, threshold Fraction) error {
	if !pr.IsOperatorEnabled() {
		return fmt.Errorf("operator is not enabled")
	} else if pr.config.OperatorsEip712Params == nil {
		return fmt.Errorf("operator EIP712 parameters are not set")
	}
	if nonce == 0 {
		return fmt.Errorf("invalid nonce: %v", nonce)
	}
	if threshold.Numerator == 0 || threshold.Denominator == 0 {
		return fmt.Errorf("invalid threshold: %s", threshold.String())
	}
	if threshold.Numerator > threshold.Denominator {
		return fmt.Errorf("new operators threshold numerator cannot be greater than denominator: %s", threshold.String())
	}
	cplatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return err
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, cplatestHeight))
	if err != nil {
		return err
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return fmt.Errorf("failed to unpack client state: client_state=%v %w", counterpartyClientRes.ClientState, err)
	}
	clientState, ok := cs.(*lcptypes.ClientState)
	if !ok {
		return fmt.Errorf("failed to cast client state: %T", cs)
	}
	if l := len(clientState.Operators); l == 0 {
		return fmt.Errorf("updateOperators is not supported in permissionless operator mode")
	} else if l > 1 {
		return fmt.Errorf("currently only one operator is supported, but got %v", l)
	}
	opSigner, err := pr.eip712Signer.GetSignerAddress(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(clientState.Operators[0], opSigner.Bytes()) {
		return fmt.Errorf("operator mismatch: expected 0x%x, but got 0x%x", clientState.Operators[0], opSigner)
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
	sig, err := pr.eip712Signer.Sign(ctx, commitment)
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
	signer, err := counterparty.GetAddress()
	if err != nil {
		return err
	}
	msg, err := clienttypes.NewMsgUpdateClient(counterparty.Path().ClientID, message, signer.String())
	if err != nil {
		return err
	}
	if _, err := counterparty.SendMsgs(ctx, []sdk.Msg{msg}); err != nil {
		return err
	}
	return nil
}

type EIP712Signer struct {
	signer signer.Signer
}

func NewEIP712Signer(signer signer.Signer) *EIP712Signer {
	return &EIP712Signer{signer: signer}
}

func (s EIP712Signer) Sign(ctx context.Context, commitment [32]byte) ([]byte, error) {
	return s.signer.Sign(ctx, commitment[:])
}

func (s EIP712Signer) GetSignerAddress(ctx context.Context) (common.Address, error) {
	pub, err := s.signer.GetPublicKey(ctx)
	if err != nil {
		return common.Address{}, err
	}
	pubKey, err := crypto.DecompressPubkey(pub)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubKey), nil
}

func decodeOperatorAddress(s string) (common.Address, error) {
	addrStr := strings.TrimPrefix(s, "0x")
	if len(addrStr) != 40 {
		return common.Address{}, fmt.Errorf("invalid operator address length %v", len(addrStr))
	}
	return common.HexToAddress(s), nil
}
