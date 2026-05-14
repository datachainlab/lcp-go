package relay

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
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
		anyHeader, err := ensureAnyHeaderForSourceUnit(unit)
		if err != nil {
			return nil, fmt.Errorf("source header unit at i=%v: %w", i, err)
		}
		anyHeaders = append(anyHeaders, anyHeader)
	}
	return anyHeaders, nil
}

// ensureAnyHeaderForSourceUnit returns the packed AnyHeader for a source unit,
// repacking from unit.Header if the packed form was released after a successful
// speculative Send. The repacked AnyHeader is cached back into the unit so a
// subsequent fallback iteration does not pay the encoding cost twice.
func ensureAnyHeaderForSourceUnit(unit *ExplicitStateSourceHeaderUnit) (*codectypes.Any, error) {
	if unit.AnyHeader != nil {
		return unit.AnyHeader, nil
	}
	if unit.Header == nil {
		return nil, fmt.Errorf("source header unit missing packed header and core header")
	}
	anyHeader, err := clienttypes.PackClientMessage(unit.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to repack source header from core header: %w", err)
	}
	unit.AnyHeader = anyHeader
	return anyHeader, nil
}
