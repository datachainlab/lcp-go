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

func collectExplicitStateSourceHeaderUnits(
	headerStream <-chan *core.HeaderOrError,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	var units []*ExplicitStateSourceHeaderUnit
	i := 0
	for h := range headerStream {
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
		units = append(units, &ExplicitStateSourceHeaderUnit{
			Header:        h.Header,
			AnyHeader:     anyHeader,
			TrustedHeight: trustedHeight,
		})
		i += 1
	}
	return units, nil
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

func explicitStateLaneLimitReason(
	sourceUnits []*ExplicitStateSourceHeaderUnit,
	laneWidths []int,
) string {
	if len(sourceUnits) == 0 {
		return "no_source_headers"
	}
	if len(sourceUnits) == 1 {
		return "single_source_header"
	}
	if len(laneWidths) > 1 {
		return ""
	}
	switch explicitStateLaneStrategy() {
	case "", "conservative":
		return "conservative_strategy"
	case "shared_trusted_height":
		if explicitStateSourceUnitsShareSingleWriteDomain(sourceUnits) {
			return "shared_write_domain"
		}
		firstTrustedHeight := sourceUnits[0].TrustedHeight
		if firstTrustedHeight == nil {
			return "missing_trusted_height"
		}
		for _, unit := range sourceUnits[1:] {
			if unit == nil || unit.TrustedHeight == nil {
				return "missing_trusted_height"
			}
			if !unit.TrustedHeight.EQ(*firstTrustedHeight) {
				return "mixed_trusted_height"
			}
		}
		return "planner_kept_single_lane"
	default:
		return ""
	}
}

func explicitStateSourceUnitsShareSingleWriteDomain(sourceUnits []*ExplicitStateSourceHeaderUnit) bool {
	if len(sourceUnits) == 0 {
		return false
	}
	for _, unit := range sourceUnits {
		if unit == nil || unit.AnyHeader == nil {
			return false
		}
		if unit.AnyHeader.TypeUrl != tendermintHeaderTypeURL {
			return false
		}
	}
	return true
}
