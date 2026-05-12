package relay

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type ExplicitStateSourceHeaderUnit struct {
	Header    core.Header
	AnyHeader *codectypes.Any
	BaseState *ExplicitStateRef
}

type ExplicitStateSourceHeaderUnitOrError struct {
	Unit  *ExplicitStateSourceHeaderUnit
	Error error
}

func makeExplicitStateSourceHeaderUnitStream(
	units []*ExplicitStateSourceHeaderUnit,
) <-chan *ExplicitStateSourceHeaderUnitOrError {
	ch := make(chan *ExplicitStateSourceHeaderUnitOrError, len(units))
	for _, unit := range units {
		ch <- &ExplicitStateSourceHeaderUnitOrError{Unit: unit}
	}
	close(ch)
	return ch
}

func drainExplicitStateSourceHeaderUnitStream(
	unitStream <-chan *ExplicitStateSourceHeaderUnitOrError,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	var units []*ExplicitStateSourceHeaderUnit
	i := 0
	for item := range unitStream {
		unit, err := explicitStateSourceHeaderUnitFromStreamItemOrError(item, i)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
		i += 1
	}
	return units, nil
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

func extractAnyHeadersFromSourceUnits(
	units []*ExplicitStateSourceHeaderUnit,
) ([]*codectypes.Any, error) {
	anyHeaders := make([]*codectypes.Any, 0, len(units))
	for i, unit := range units {
		if unit == nil {
			return nil, fmt.Errorf("source header unit must not be nil: i=%v", i)
		}
		if unit.AnyHeader == nil {
			return nil, fmt.Errorf("source header unit missing packed header: i=%v", i)
		}
		anyHeaders = append(anyHeaders, unit.AnyHeader)
	}
	return anyHeaders, nil
}
