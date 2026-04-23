package relay

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type ExplicitStateSourceHeaderUnit struct {
	Header        core.Header
	AnyHeader     *codectypes.Any
	TrustedHeight *clienttypes.Height
	BaseState     *ExplicitStateRef
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

func collectExplicitStateSourceHeaderUnits(
	headerStream <-chan *core.HeaderOrError,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	var units []*ExplicitStateSourceHeaderUnit
	i := 0
	for h := range headerStream {
		unit, err := explicitStateSourceHeaderUnitFromStreamItem(h, i)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
		i += 1
	}
	return units, nil
}

func explicitStateSourceHeaderUnitFromStreamItem(
	h *core.HeaderOrError,
	i int,
) (*ExplicitStateSourceHeaderUnit, error) {
	if h == nil {
		return nil, fmt.Errorf("received nil header stream item: i=%v", i)
	}
	if h.Error != nil {
		return nil, fmt.Errorf("failed to setup a header for update: i=%v %w", i, h.Error)
	}
	if h.Header == nil {
		return nil, fmt.Errorf("received nil header in header stream: i=%v", i)
	}
	anyHeader, err := clienttypes.PackClientMessage(h.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to pack header: i=%v header=%v %w", i, h.Header, err)
	}
	trustedHeight, err := trustedHeightForExplicitState(anyHeader, nil)
	if err != nil {
		return nil, err
	}
	return &ExplicitStateSourceHeaderUnit{
		Header:        h.Header,
		AnyHeader:     anyHeader,
		TrustedHeight: trustedHeight,
	}, nil
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
	if item.Unit.TrustedHeight == nil {
		trustedHeight, err := trustedHeightForExplicitState(item.Unit.AnyHeader, nil)
		if err != nil {
			return nil, err
		}
		item.Unit.TrustedHeight = trustedHeight
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

func extractExplicitStateHeaderUnits(
	units []*ExplicitStateSourceHeaderUnit,
) []*ExplicitStateHeaderUnit {
	headerUnits := make([]*ExplicitStateHeaderUnit, 0, len(units))
	for _, unit := range units {
		if unit == nil {
			continue
		}
		headerUnits = append(headerUnits, &ExplicitStateHeaderUnit{
			Header:        unit.AnyHeader,
			TrustedHeight: unit.TrustedHeight,
			BaseState:     cloneExplicitStateRef(unit.BaseState),
		})
	}
	return headerUnits
}
