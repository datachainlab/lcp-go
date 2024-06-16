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
	switch pc.OperatorsEip712Salt.(type) {
	case *ProverConfig_EvmChainEip712Salt:
		return ChainTypeEVM
	case *ProverConfig_CosmosChainEip712Salt:
		return ChainTypeCosmos
	default:
		panic(fmt.Sprintf("unknown chain salt: %v", pc.OperatorsEip712Salt))
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
		return fmt.Errorf("Operators: greater than 1 operator is not supported yet")
	}
	if pc.OperatorsEip712Salt != nil {
		if len(pc.OperatorPrivateKey) == 0 {
			return fmt.Errorf("OperatorPrivateKey must be set if OperatorsEip712Salt is set")
		}
		switch salt := pc.OperatorsEip712Salt.(type) {
		case *ProverConfig_EvmChainEip712Salt:
			if salt.EvmChainEip712Salt.ChainId == 0 {
				return fmt.Errorf("OperatorsEip712Salt: EvmChainSalt.ChainId must be set")
			}
			if !common.IsHexAddress(salt.EvmChainEip712Salt.VerifyingContractAddress) {
				return fmt.Errorf("OperatorsEip712Salt: EvmChainSalt.VerifyingContractAddress must be a valid hex address")
			}
		case *ProverConfig_CosmosChainEip712Salt:
			if salt.CosmosChainEip712Salt.ChainId == "" {
				return fmt.Errorf("OperatorsEip712Salt: CosmosChainSalt.ChainId must be set")
			}
			if salt.CosmosChainEip712Salt.Prefix == "" {
				return fmt.Errorf("OperatorsEip712Salt: CosmosChainSalt.Prefix must be set")
			}
		default:
			return fmt.Errorf("OperatorsEip712Salt: unknown type")
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
