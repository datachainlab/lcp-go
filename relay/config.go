package relay

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/hyperledger-labs/yui-relayer/core"
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
	return nil
}

func decodeMrenclaveHex(s string) ([]byte, error) {
	s = strings.ToLower(strings.TrimPrefix(s, "0x"))
	return hex.DecodeString(s)
}
