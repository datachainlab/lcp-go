package relay

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

const (
	DefaultDialTimeout                 = 20 // seconds
	DefaultMessageAggregationBatchSize = 8
)

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

func (pc ProverConfig) ChainType() lcptypes.ChainType {
	switch pc.OperatorsEip712Params.(type) {
	case *ProverConfig_OperatorsEip712EvmChainParams:
		return lcptypes.ChainTypeEVM
	case *ProverConfig_OperatorsEip712CosmosChainParams:
		return lcptypes.ChainTypeCosmos
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
	} else if l == 0 {
		return nil
	}

	// ----- operators config validation -----

	if pc.OperatorSigner == nil {
		return fmt.Errorf("OperatorSigner must be set if Operators or OperatorsEip712Params is set")
	}
	{
		signerConfig, ok := pc.OperatorSigner.GetCachedValue().(signer.SignerConfig)
		if !ok {
			return fmt.Errorf("failed to cast OperatorSigner's config: %T", pc.OperatorSigner.GetCachedValue())
		} else if err := signerConfig.Validate(); err != nil {
			return fmt.Errorf("failed to validate the OperatorSigner's config: %v", err)
		}
		signer, err := signerConfig.Build()
		if err != nil {
			return fmt.Errorf("failed to build the OperatorSigner: %v", err)
		}
		addr, err := NewEIP712Signer(signer).GetSignerAddress()
		if err != nil {
			return fmt.Errorf("failed to get the OperatorSigner's address: %v", err)
		}
		op, err := decodeOperatorAddress(pc.Operators[0])
		if err != nil {
			return fmt.Errorf("failed to decode operator address: %v", err)
		}
		if addr != op {
			return fmt.Errorf("OperatorSigner's address must be equal to the first operator's address: %v != %v", addr, op)
		}
	}
	if pc.OperatorsEip712Params != nil {
		switch params := pc.OperatorsEip712Params.(type) {
		case *ProverConfig_OperatorsEip712EvmChainParams:
			if params.OperatorsEip712EvmChainParams.ChainId == 0 {
				return fmt.Errorf("OperatorsEip712EvmChainParams.ChainId must be set")
			}
			if !common.IsHexAddress(params.OperatorsEip712EvmChainParams.VerifyingContractAddress) {
				return fmt.Errorf("OperatorsEip712EvmChainParams.VerifyingContractAddress must be a valid hex address")
			}
		case *ProverConfig_OperatorsEip712CosmosChainParams:
			if params.OperatorsEip712CosmosChainParams.ChainId == "" {
				return fmt.Errorf("OperatorsEip712CosmosChainParams.ChainId must be set")
			}
			if params.OperatorsEip712CosmosChainParams.Prefix == "" {
				return fmt.Errorf("OperatorsEip712CosmosChainParams.Prefix must be set")
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

func (pr *Prover) getRAType() RAType {
	switch t := pr.config.ZkvmConfig.(type) {
	case *ProverConfig_Risc0ZkvmConfig:
		if t.Risc0ZkvmConfig.Mock {
			return RATypeMockZKDCAPRisc0
		} else {
			return RATypeZKDCAPRisc0
		}
	default:
		return RATypeIAS
	}
}

func (pr *Prover) getZKDCAPVerifierInfos() ([][]byte, error) {
	raType := pr.getRAType()
	switch raType {
	case RATypeIAS, RATypeDCAP:
		return nil, nil
	case RATypeZKDCAPRisc0, RATypeMockZKDCAPRisc0:
		bz, err := pr.config.GetRisc0ZkvmConfig().getZKDCAPVerifierInfo()
		if err != nil {
			return nil, err
		}
		return [][]byte{bz[:]}, nil
	default:
		return nil, fmt.Errorf("unsupported RA type: %v", raType)
	}
}

func (c *Risc0ZKVMConfig) getZKDCAPVerifierInfo() ([64]byte, error) {
	var verifierInfo [64]byte
	imageID := c.GetImageID()
	verifierInfo[0] = byte(dcap.Risc0ZKVMType)
	copy(verifierInfo[32:], imageID[:])
	return verifierInfo, nil
}

func (c *Risc0ZKVMConfig) GetImageID() [32]byte {
	imageID := common.FromHex(c.ImageId)
	if len(imageID) != 32 {
		panic(fmt.Sprintf("invalid image ID: %v", c.ImageId))
	}
	var id [32]byte
	copy(id[:], imageID)
	return id
}
