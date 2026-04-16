package relay

import (
	"context"
	"fmt"
	"os"
	"strconv"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	"github.com/hyperledger-labs/yui-relayer/core"
)

const envExplicitStateTMMultiHeaderCollector = "YRLY_LCP_EXPLICIT_STATE_TM_MULTI_HEADER_COLLECTOR"
const envExplicitStateTMMultiHeaderLimit = "YRLY_LCP_EXPLICIT_STATE_TM_MULTI_HEADER_LIMIT"
const defaultExplicitStateTMMultiHeaderLimit = 4

type ExplicitStateSourceHeaderUnit struct {
	Header        core.Header
	AnyHeader     *codectypes.Any
	TrustedHeight *clienttypes.Height
	BaseState     *ExplicitStateRef
}

type explicitStateCounterpartyClientStateQuerier interface {
	LatestHeight(ctx context.Context) (ibcexported.Height, error)
	QueryClientState(ctx core.QueryContext) (*clienttypes.QueryClientStateResponse, error)
}

type explicitStateTMHeaderProvider interface {
	UpdateLightClient(ctx context.Context, height int64) (*tmclienttypes.Header, error)
}

type explicitStateTMValsetQuerier interface {
	QueryValsetAtHeight(ctx context.Context, height clienttypes.Height) (*tmproto.ValidatorSet, error)
}

func useExplicitStateTMMultiHeaderCollector() bool {
	switch os.Getenv(envExplicitStateTMMultiHeaderCollector) {
	case "1", "true", "TRUE", "True":
		return true
	default:
		return false
	}
}

func explicitStateTMMultiHeaderLimit() int {
	v, ok := os.LookupEnv(envExplicitStateTMMultiHeaderLimit)
	if !ok || v == "" {
		return defaultExplicitStateTMMultiHeaderLimit
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultExplicitStateTMMultiHeaderLimit
	}
	return n
}

func collectExplicitStateSourceHeaderUnits(
	headerStream <-chan *core.HeaderOrError,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	var units []*ExplicitStateSourceHeaderUnit
	for h := range headerStream {
		if h == nil {
			return nil, fmt.Errorf("received nil header stream item")
		}
		if h.Error != nil {
			return nil, fmt.Errorf("failed to setup a header for update: %w", h.Error)
		}
		if h.Header == nil {
			return nil, fmt.Errorf("received nil header in header stream")
		}
		anyHeader, err := clienttypes.PackClientMessage(h.Header)
		if err != nil {
			return nil, fmt.Errorf("failed to pack header: header=%v %w", h.Header, err)
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
	}
	return units, nil
}

func extractAnyHeadersFromSourceUnits(
	units []*ExplicitStateSourceHeaderUnit,
) []*codectypes.Any {
	anyHeaders := make([]*codectypes.Any, 0, len(units))
	for _, unit := range units {
		if unit == nil || unit.AnyHeader == nil {
			continue
		}
		anyHeaders = append(anyHeaders, unit.AnyHeader)
	}
	return anyHeaders
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

func collectTendermintSharedTrustedSourceHeaderUnits(
	ctx context.Context,
	cdc codectypes.AnyUnpacker,
	counterparty explicitStateCounterpartyClientStateQuerier,
	headerProvider explicitStateTMHeaderProvider,
	valsetQuerier explicitStateTMValsetQuerier,
	latestFinalizedHeader core.Header,
	maxHeaders int,
) ([]*ExplicitStateSourceHeaderUnit, bool, error) {
	latestHeader, ok := latestFinalizedHeader.(*tmclienttypes.Header)
	if !ok || latestHeader == nil {
		return nil, false, nil
	}
	cpLatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get counterparty latest height: %w", err)
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, cpLatestHeight))
	if err != nil {
		return nil, false, fmt.Errorf("failed to query counterparty client state: %w", err)
	}
	var cs ibcexported.ClientState
	if err := cdc.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return nil, false, fmt.Errorf("failed to unpack counterparty client state: %w", err)
	}
	trustedHeight, ok := cs.GetLatestHeight().(clienttypes.Height)
	if !ok || trustedHeight.IsZero() {
		return nil, false, nil
	}
	latestHeight := latestHeader.GetHeight().(clienttypes.Height)
	if !trustedHeight.LT(latestHeight) {
		return nil, false, nil
	}
	targetHeights := buildExplicitStateTMTargetHeights(
		trustedHeight.RevisionHeight,
		latestHeight.RevisionHeight,
		maxHeaders,
	)
	var units []*ExplicitStateSourceHeaderUnit
	currentTrustedHeight := trustedHeight
	for _, h := range targetHeights {
		trustedValset, err := valsetQuerier.QueryValsetAtHeight(ctx, currentTrustedHeight)
		if err != nil {
			return nil, false, fmt.Errorf("failed to query trusted validators at %s: %w", currentTrustedHeight, err)
		}
		header, err := headerProvider.UpdateLightClient(ctx, int64(h))
		if err != nil {
			return nil, false, fmt.Errorf("failed to update tendermint light client at height %d: %w", h, err)
		}
		header.TrustedHeight = currentTrustedHeight
		header.TrustedValidators = trustedValset
		anyHeader, err := clienttypes.PackClientMessage(header)
		if err != nil {
			return nil, false, fmt.Errorf("failed to pack tendermint header at height %d: %w", h, err)
		}
		unitTrustedHeight := currentTrustedHeight
		units = append(units, &ExplicitStateSourceHeaderUnit{
			Header:        header,
			AnyHeader:     anyHeader,
			TrustedHeight: &unitTrustedHeight,
		})
		currentTrustedHeight = clienttypes.NewHeight(currentTrustedHeight.RevisionNumber, h)
	}
	if len(units) < 2 {
		return nil, false, nil
	}
	return units, true, nil
}

func buildExplicitStateTMTargetHeights(trustedHeight, latestHeight uint64, maxHeaders int) []uint64 {
	if latestHeight <= trustedHeight {
		return nil
	}
	total := latestHeight - trustedHeight
	if maxHeaders <= 0 || total <= uint64(maxHeaders) {
		targets := make([]uint64, 0, total)
		for h := trustedHeight + 1; h <= latestHeight; h++ {
			targets = append(targets, h)
		}
		return targets
	}
	targets := make([]uint64, 0, maxHeaders)
	var prev uint64
	maxHeadersU64 := uint64(maxHeaders)
	for i := 1; i <= maxHeaders; i++ {
		h := trustedHeight + (uint64(i)*total+maxHeadersU64-1)/maxHeadersU64
		if h <= prev {
			continue
		}
		targets = append(targets, h)
		prev = h
	}
	if len(targets) == 0 || targets[len(targets)-1] != latestHeight {
		targets = append(targets, latestHeight)
	}
	return targets
}
