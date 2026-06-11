package relay

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type ExplicitStateBase struct {
	Height         clienttypes.Height
	ClientState    *codectypes.Any
	ConsensusState *codectypes.Any
	// StateId is the state ID committed for this base when known (e.g. taken
	// from the on-chain LCP consensus state). Empty when only the LCP canonical
	// base is available. When set, the relayer threads it into the first unit's
	// prev_state_id so LCP verifies the speculative chain anchors at exactly
	// this state.
	StateId []byte
}

type ExplicitStateSourceHeaderUnit struct {
	Header    core.Header
	AnyHeader *codectypes.Any
	BaseState *ExplicitStateRef
}

type ExplicitStateSourceHeaderUnitOrError struct {
	Unit  *ExplicitStateSourceHeaderUnit
	Error error
}

func drainExplicitStateSourceHeaderUnitStreamDiscard(
	unitStream <-chan *ExplicitStateSourceHeaderUnitOrError,
) {
	for range unitStream {
	}
}

func explicitStateSourceHeaderUnitFromStreamItemOrError(
	item *ExplicitStateSourceHeaderUnitOrError,
	i int,
) (*ExplicitStateSourceHeaderUnit, error) {
	if item == nil {
		return nil, fmt.Errorf("received nil explicit-state source header stream item: i=%v", i)
	}
	if item.Error != nil {
		return nil, fmt.Errorf("failed to setup an explicit-state source header unit: i=%v %w", i, item.Error)
	}
	if item.Unit == nil {
		return nil, fmt.Errorf("received nil explicit-state source header unit: i=%v", i)
	}
	if item.Unit.AnyHeader == nil {
		return nil, fmt.Errorf("explicit-state source header unit missing packed header: i=%v", i)
	}
	return item.Unit, nil
}
