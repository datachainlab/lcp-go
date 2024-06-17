package relay

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

const (
	DefaultDialTimeout                 = 20 // seconds
	DefaultMessageAggregationBatchSize = 8

	ChainTypeEVM    ChainType = 1
	ChainTypeCosmos ChainType = 2
)

type ChainType uint16

func (t ChainType) String() string {
	switch t {
	case ChainTypeEVM:
		return "EVM"
	case ChainTypeCosmos:
		return "Cosmos"
	default:
		return fmt.Sprintf("UnknownChainType(%d)", t.Uint16())
	}
}

func (t ChainType) Uint16() uint16 {
	return uint16(t)
}

var _ core.ProverConfig = (*ProverConfig)(nil)

var _ codectypes.UnpackInterfacesMessage = (*ProverConfig)(nil)

func (cfg *ProverConfig) UnpackInterfaces(unpacker codectypes.AnyUnpacker) error {
	if cfg == nil {
		return nil
	}
	if err := unpacker.UnpackAny(cfg.OriginProver, new(core.ProverConfig)); err != nil {
		return err
	}
	if cfg.OperatorSigner != nil {
		if err := unpacker.UnpackAny(cfg.OperatorSigner, new(signer.SignerConfig)); err != nil {
			return err
		}
	}
	return nil
}

func (pc ProverConfig) Build(chain core.Chain) (core.Prover, error) {
	if err := pc.Validate(); err != nil {
		return nil, err
	}
	prover, err := pc.OriginProver.GetCachedValue().(core.ProverConfig).Build(chain)
	if err != nil {
		return nil, err
	}
	return NewProver(pc, chain, prover)
}

func (pc ProverConfig) GetDialTimeout() time.Duration {
	if pc.LcpServiceDialTimeout == 0 {
		return DefaultDialTimeout * time.Second
	} else {
		return time.Duration(pc.LcpServiceDialTimeout) * time.Second
	}
}

func (pc ProverConfig) GetMrenclave() []byte {
	mrenclave, err := decodeMrenclaveHex(pc.Mrenclave)
	if err != nil {
		panic(err)
	}
	return mrenclave
}

func (pc ProverConfig) GetMessageAggregationBatchSize() uint64 {
	if pc.MessageAggregationBatchSize == 0 {
		return DefaultMessageAggregationBatchSize
	} else {
		return pc.MessageAggregationBatchSize
	}
}

func (pc ProverConfig) ChainType() ChainType {
	switch pc.OperatorsEip712Params.(type) {
	case *ProverConfig_OperatorsEvmChainEip712Params:
		return ChainTypeEVM
	case *ProverConfig_OperatorsCosmosChainEip712Params:
		return ChainTypeCosmos
	default:
		panic(fmt.Sprintf("unknown chain params: %v", pc.OperatorsEip712Params))
	}
}

func (pc ProverConfig) Validate() error {
	// origin prover config validation
	if err := pc.OriginProver.GetCachedValue().(core.ProverConfig).Validate(); err != nil {
		return fmt.Errorf("failed to validate the origin prover's config: %v", err)
	}

	// lcp prover config validation
	mrenclave, err := decodeMrenclaveHex(pc.Mrenclave)
	if err != nil {
		return err
	}
	if l := len(mrenclave); l != lcptypes.MrenclaveSize {
		return fmt.Errorf("MRENCLAVE length must be %v, but got %v", lcptypes.MrenclaveSize, l)
	}
	if pc.KeyExpiration == 0 {
		return fmt.Errorf("KeyExpiration must be greater than 0")
	}
	if pc.MessageAggregation && pc.MessageAggregationBatchSize == 1 {
		return fmt.Errorf("MessageAggregationBatchSize must be greater than 1 if MessageAggregation is true and MessageAggregationBatchSize is set")
	}
	if l := len(pc.Operators); l > 1 {
		return fmt.Errorf("Operators: currently only one or zero(=permissionless) operator is supported, but got %v", l)
	}
	if pc.OperatorsEip712Params != nil {
		if pc.OperatorSigner == nil {
			return fmt.Errorf("OperatorSigner must be set if OperatorsEip712Params is set")
		}
		signerConfig, ok := pc.OperatorSigner.GetCachedValue().(signer.SignerConfig)
		if !ok {
			return fmt.Errorf("failed to cast OperatorSigner's config: %T", pc.OperatorSigner.GetCachedValue())
		} else if err := signerConfig.Validate(); err != nil {
			return fmt.Errorf("failed to validate the OperatorSigner's config: %v", err)
		}
		switch salt := pc.OperatorsEip712Params.(type) {
		case *ProverConfig_OperatorsEvmChainEip712Params:
			if salt.OperatorsEvmChainEip712Params.ChainId == 0 {
				return fmt.Errorf("OperatorsEvmChainEip712Params.ChainId must be set")
			}
			if !common.IsHexAddress(salt.OperatorsEvmChainEip712Params.VerifyingContractAddress) {
				return fmt.Errorf("OperatorsEvmChainEip712Params.VerifyingContractAddress must be a valid hex address")
			}
		case *ProverConfig_OperatorsCosmosChainEip712Params:
			if salt.OperatorsCosmosChainEip712Params.ChainId == "" {
				return fmt.Errorf("OperatorsCosmosChainEip712Params.ChainId must be set")
			}
			if salt.OperatorsCosmosChainEip712Params.Prefix == "" {
				return fmt.Errorf("OperatorsCosmosChainEip712Params.Prefix must be set")
			}
		default:
			return fmt.Errorf("OperatorsEip712Params: unknown type")
		}
	}
	return nil
}

func decodeMrenclaveHex(s string) ([]byte, error) {
	trimmed := strings.ToLower(strings.TrimPrefix(s, "0x"))
	bz, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MRENCLAVE: value=%v %w", s, err)
	}
	return bz, nil
}
