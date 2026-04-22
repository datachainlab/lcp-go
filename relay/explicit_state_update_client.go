package relay

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	gogoproto "github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

const envExplicitStateUpdateClient = "YRLY_LCP_USE_EXPLICIT_STATE_UPDATE_CLIENT"
const envExplicitStateLaneStrategy = "YRLY_LCP_EXPLICIT_STATE_LANE_STRATEGY"
const queryClientMethod = "/lcp.service.elc.v1.Query/Client"
const tendermintHeaderTypeURL = "/ibc.lightclients.tendermint.v1.Header"

func useExplicitStateUpdateClient() bool {
	v, ok := os.LookupEnv(envExplicitStateUpdateClient)
	if !ok {
		return false
	}
	switch v {
	case "1", "true", "TRUE", "True":
		return true
	default:
		return false
	}
}

func (pr *Prover) buildExplicitStateUpdatePlanForHeaders(
	ctx context.Context,
	anyHeaders []*codectypes.Any,
	elcClientID string,
	includeState bool,
	signer []byte,
) (*ExplicitStateUpdatePlan, error) {
	headerUnits, err := buildExplicitStateHeaderUnits(anyHeaders)
	if err != nil {
		return nil, err
	}
	return pr.buildExplicitStateUpdatePlanForHeaderUnits(ctx, headerUnits, elcClientID, includeState, signer)
}

func (pr *Prover) buildExplicitStateUpdatePlanForHeaderUnits(
	ctx context.Context,
	headerUnits []*ExplicitStateHeaderUnit,
	elcClientID string,
	includeState bool,
	signer []byte,
) (*ExplicitStateUpdatePlan, error) {
	headerLanes, err := planExplicitStateHeaderLanes(headerUnits)
	if err != nil {
		return nil, err
	}
	return pr.buildExplicitStateUpdatePlanForHeaderLanes(
		ctx,
		headerLanes,
		elcClientID,
		includeState,
		signer,
	)
}

func planExplicitStateHeaderLanes(headerUnits []*ExplicitStateHeaderUnit) ([][]*ExplicitStateHeaderUnit, error) {
	strategy := explicitStateLaneStrategy()
	switch strategy {
	case "":
		return planConservativeExplicitStateHeaderLanes(headerUnits)
	case "conservative":
		return planConservativeExplicitStateHeaderLanes(headerUnits)
	case "shared_trusted_height":
		return planSharedTrustedHeightExplicitStateLanes(headerUnits)
	case "single_header":
		return planSingleHeaderExplicitStateLanes(headerUnits)
	default:
		return nil, fmt.Errorf(
			"unsupported explicit-state lane strategy: %s",
			strategy,
		)
	}
}

func explicitStateHeaderLaneWidths(headerLanes [][]*ExplicitStateHeaderUnit) []int {
	laneWidths := make([]int, 0, len(headerLanes))
	for _, lane := range headerLanes {
		laneWidths = append(laneWidths, len(lane))
	}
	return laneWidths
}

func countExplicitStateHeaderLaneUnits(headerLanes [][]*ExplicitStateHeaderUnit) int {
	var count int
	for _, lane := range headerLanes {
		count += len(lane)
	}
	return count
}

func explicitStateLaneStrategy() string {
	return os.Getenv(envExplicitStateLaneStrategy)
}

func explicitStateHeaderUnitsHaveEmbeddedBaseState(headerUnits []*ExplicitStateHeaderUnit) bool {
	if len(headerUnits) == 0 {
		return false
	}
	for _, unit := range headerUnits {
		if unit == nil || unit.Header == nil || unit.BaseState == nil {
			return false
		}
	}
	return true
}

func countExplicitStateHeaderUnitsWithCompleteBaseState(headerUnits []*ExplicitStateHeaderUnit) int {
	count := 0
	for _, unit := range headerUnits {
		if canHeaderUnitStartIndependentLane(unit) {
			count++
		}
	}
	return count
}

func planConservativeExplicitStateHeaderLanes(headerUnits []*ExplicitStateHeaderUnit) ([][]*ExplicitStateHeaderUnit, error) {
	if len(headerUnits) == 0 {
		return nil, nil
	}
	for i, unit := range headerUnits {
		if unit == nil || unit.Header == nil {
			return nil, fmt.Errorf("explicit-state header unit[%d] must not be nil", i)
		}
	}
	// Keep a single linear lane until the relayer can prove wider independence.
	return [][]*ExplicitStateHeaderUnit{append([]*ExplicitStateHeaderUnit(nil), headerUnits...)}, nil
}

func planSingleHeaderExplicitStateLanes(headerUnits []*ExplicitStateHeaderUnit) ([][]*ExplicitStateHeaderUnit, error) {
	if len(headerUnits) == 0 {
		return nil, nil
	}
	var lanes [][]*ExplicitStateHeaderUnit
	var currentLane []*ExplicitStateHeaderUnit
	for i, unit := range headerUnits {
		if unit == nil || unit.Header == nil {
			return nil, fmt.Errorf("explicit-state header unit[%d] must not be nil", i)
		}
		if i == 0 || canHeaderUnitStartIndependentLane(unit) {
			if len(currentLane) > 0 {
				lanes = append(lanes, currentLane)
			}
			currentLane = []*ExplicitStateHeaderUnit{unit}
			continue
		}
		currentLane = append(currentLane, unit)
	}
	if len(currentLane) > 0 {
		lanes = append(lanes, currentLane)
	}
	return lanes, nil
}

func canHeaderUnitStartIndependentLane(unit *ExplicitStateHeaderUnit) bool {
	if unit == nil || unit.TrustedHeight == nil {
		return false
	}
	if !hasCanonicalExplicitStatePayload(unit.BaseState) {
		return false
	}
	return unit.BaseState.PrevHeight.EQ(*unit.TrustedHeight)
}

func planSharedTrustedHeightExplicitStateLanes(
	headerUnits []*ExplicitStateHeaderUnit,
) ([][]*ExplicitStateHeaderUnit, error) {
	if len(headerUnits) == 0 {
		return nil, nil
	}
	for i, unit := range headerUnits {
		if unit == nil || unit.Header == nil {
			return nil, fmt.Errorf("explicit-state header unit[%d] must not be nil", i)
		}
	}

	firstTrustedHeight := headerUnits[0].TrustedHeight
	if firstTrustedHeight == nil {
		return planConservativeExplicitStateHeaderLanes(headerUnits)
	}

	for i := 1; i < len(headerUnits); i++ {
		trustedHeight := headerUnits[i].TrustedHeight
		if trustedHeight == nil || !trustedHeight.EQ(*firstTrustedHeight) {
			return planConservativeExplicitStateHeaderLanes(headerUnits)
		}
	}
	if explicitStateHeadersShareSingleWriteDomain(headerUnits) {
		return planConservativeExplicitStateHeaderLanes(headerUnits)
	}
	return planSingleHeaderExplicitStateLanes(headerUnits)
}

func explicitStateHeadersShareSingleWriteDomain(headerUnits []*ExplicitStateHeaderUnit) bool {
	if len(headerUnits) == 0 {
		return false
	}
	for _, unit := range headerUnits {
		if unit == nil || unit.Header == nil {
			return false
		}
		if unit.Header.TypeUrl != tendermintHeaderTypeURL {
			return false
		}
	}
	return true
}

func (pr *Prover) buildExplicitStateUpdatePlanForHeaderLanes(
	ctx context.Context,
	headerLanes [][]*ExplicitStateHeaderUnit,
	elcClientID string,
	includeState bool,
	signer []byte,
) (*ExplicitStateUpdatePlan, error) {
	return pr.buildExplicitStateUpdatePlanForHeaderLanesWithResolver(
		ctx,
		headerLanes,
		elcClientID,
		includeState,
		signer,
		func(ctx context.Context, elcClientID string, anyHeader *codectypes.Any) (*ExplicitStateRef, error) {
			return pr.queryExplicitStateRef(ctx, elcClientID, anyHeader)
		},
	)
}

func (pr *Prover) buildExplicitStateUpdatePlanForHeaderLanesWithResolver(
	ctx context.Context,
	headerLanes [][]*ExplicitStateHeaderUnit,
	elcClientID string,
	includeState bool,
	signer []byte,
	resolveBaseState func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error),
) (*ExplicitStateUpdatePlan, error) {
	updateLanes := make([][]*elc.MsgUpdateClient, 0, len(headerLanes))
	baseStateLanes := make([][]*ExplicitStateRef, 0, len(headerLanes))
	for laneIndex, lane := range headerLanes {
		updateLane := make([]*elc.MsgUpdateClient, 0, len(lane))
		baseStateLane := make([]*ExplicitStateRef, 0, len(lane))
		for unitIndex, unitHeader := range lane {
			if unitHeader == nil || unitHeader.Header == nil {
				return nil, fmt.Errorf("header lane %d contains nil header unit", laneIndex)
			}
			var baseState *ExplicitStateRef
			if unitHeader.BaseState != nil {
				baseState = cloneExplicitStateRef(unitHeader.BaseState)
				if err := validateExplicitStateBaseStateHeight(unitHeader, baseState); err != nil {
					return nil, err
				}
			} else if unitIndex == 0 {
				var err error
				baseState, err = resolveBaseState(ctx, elcClientID, unitHeader.Header)
				if err != nil {
					return nil, err
				}
			} else {
				var err error
				baseState, err = buildDeferredExplicitStateRef(unitHeader.Header, pr.codec)
				if err != nil {
					return nil, err
				}
			}
			updateLane = append(updateLane, &elc.MsgUpdateClient{
				ClientId:     elcClientID,
				Header:       unitHeader.Header,
				IncludeState: includeState,
				Signer:       signer,
			})
			baseStateLane = append(baseStateLane, baseState)
		}
		updateLanes = append(updateLanes, updateLane)
		baseStateLanes = append(baseStateLanes, baseStateLane)
	}
	return newLaneExplicitStateUpdatePlan(elcClientID, updateLanes, baseStateLanes)
}

func (pr *Prover) executeExplicitStateHeaderLanesStream(
	ctx context.Context,
	headerLanes [][]*ExplicitStateHeaderUnit,
	elcClientID string,
	includeState bool,
	signer []byte,
) ([]*elcupdater_storage.UpdateClientResult, error) {
	return pr.executeExplicitStateHeaderLanesStreamWithResolver(
		ctx,
		headerLanes,
		elcClientID,
		includeState,
		signer,
		func(ctx context.Context, elcClientID string, anyHeader *codectypes.Any) (*ExplicitStateRef, error) {
			return pr.queryExplicitStateRef(ctx, elcClientID, anyHeader)
		},
	)
}

func (pr *Prover) executeExplicitStateHeaderLanesStreamWithResolver(
	ctx context.Context,
	headerLanes [][]*ExplicitStateHeaderUnit,
	elcClientID string,
	includeState bool,
	signer []byte,
	resolveBaseState func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error),
) ([]*elcupdater_storage.UpdateClientResult, error) {
	totalUnits := countExplicitStateHeaderLaneUnits(headerLanes)
	results := make([]*elcupdater_storage.UpdateClientResult, 0, totalUnits)
	if totalUnits == 0 {
		return results, nil
	}
	maxUnits := pr.config.GetMaxSpeculativeBatchUnitsPerRequest()
	if err := validateExplicitStateHeaderLaneBatchBoundaries(headerLanes, maxUnits); err != nil {
		return nil, err
	}

	numBatches := (totalUnits + maxUnits - 1) / maxUnits
	if numBatches > 1 {
		pr.getLogger().InfoContext(
			ctx,
			"split speculative update client batch",
			"client_id", elcClientID,
			"num_units", totalUnits,
			"num_batches", numBatches,
			"batch_limit", maxUnits,
		)
	}

	var sender *speculativeBatchStreamSender
	closed := true
	batchSigners := make([][]byte, 0, maxUnits)
	batchIndex := 0
	unitIndex := 0
	defer func() {
		if !closed && sender != nil {
			_ = sender.CloseSend()
		}
	}()

	openBatch := func() error {
		if sender != nil {
			return nil
		}
		numUnits := min(maxUnits, totalUnits-unitIndex)
		pr.getLogger().InfoContext(
			ctx,
			"invoke speculative update client batch",
			"client_id", elcClientID,
			"num_units", numUnits,
			"batch_index", batchIndex,
			"num_batches", numBatches,
		)
		nextSender, err := openSpeculativeUpdateClientBatchStream(
			ctx,
			pr.lcpServiceClient,
			elcClientID,
			pr.config.GetMaxChunkSizeForUpdateClient(),
		)
		if err != nil {
			return err
		}
		sender = nextSender
		closed = false
		return nil
	}

	flushBatch := func() error {
		if sender == nil {
			return nil
		}
		resp, err := sender.CloseAndRecv()
		closed = true
		if err != nil {
			return fmt.Errorf("failed explicit-state update client batch: %w", err)
		}
		if len(resp.Units) != len(batchSigners) {
			return fmt.Errorf("unexpected speculative batch response shape: units=%d plan=%d", len(resp.Units), len(batchSigners))
		}
		for i, unit := range resp.Units {
			if unit == nil || unit.Response == nil {
				return fmt.Errorf("unexpected speculative batch response unit at index %d", i)
			}
			results = append(results, &elcupdater_storage.UpdateClientResult{
				Message:   unit.Response.Message,
				Signature: unit.Response.Signature,
				Signer:    batchSigners[i],
			})
		}
		sender = nil
		batchSigners = batchSigners[:0]
		batchIndex++
		return nil
	}

	for laneIndex, lane := range headerLanes {
		for unitIndexInLane, unitHeader := range lane {
			if unitHeader == nil || unitHeader.Header == nil {
				return nil, fmt.Errorf("header lane %d contains nil header unit", laneIndex)
			}
			var baseState *ExplicitStateRef
			if unitHeader.BaseState != nil {
				baseState = cloneExplicitStateRef(unitHeader.BaseState)
				if err := validateExplicitStateBaseStateHeight(unitHeader, baseState); err != nil {
					return nil, err
				}
			} else if unitIndexInLane == 0 {
				var err error
				baseState, err = resolveBaseState(ctx, elcClientID, unitHeader.Header)
				if err != nil {
					return nil, err
				}
			} else {
				var err error
				baseState, err = buildDeferredExplicitStateRef(unitHeader.Header, pr.codec)
				if err != nil {
					return nil, err
				}
			}

			unit := &ExplicitStatePlannedUnit{
				UnitID: buildSpeculativeUnitID(unitIndex),
				Update: &elc.MsgUpdateClient{
					ClientId:     elcClientID,
					Header:       unitHeader.Header,
					IncludeState: includeState,
					Signer:       signer,
				},
				BaseState: baseState,
			}
			if sender == nil && unitIndex > 0 && !canStartIndependentExplicitStateBatch(unit) {
				return nil, fmt.Errorf(
					"cannot split explicit-state plan at unit %s: missing base state payload",
					unit.UnitID,
				)
			}

			if err := openBatch(); err != nil {
				return nil, err
			}
			if err := sender.Send(&SpeculativeUpdateClientUnit{
				UnitId:    unit.UnitID,
				Update:    unit.Update,
				BaseState: unit.BaseState,
			}); err != nil {
				err, _ = sender.enrichSendError(err)
				return nil, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", len(batchSigners), unit.UnitID, err)
			}
			batchSigners = append(batchSigners, unit.Update.Signer)
			unitIndex++

			if len(batchSigners) == maxUnits {
				if err := flushBatch(); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := flushBatch(); err != nil {
		return nil, err
	}
	return results, nil
}

func validateExplicitStateHeaderLaneBatchBoundaries(
	headerLanes [][]*ExplicitStateHeaderUnit,
	maxUnits int,
) error {
	if maxUnits <= 0 {
		return nil
	}
	unitIndex := 0
	for laneIndex, lane := range headerLanes {
		for unitIndexInLane, unitHeader := range lane {
			if unitIndex > 0 && unitIndex%maxUnits == 0 {
				if !canHeaderUnitStartIndependentExplicitStateBatch(unitIndexInLane, unitHeader) {
					return fmt.Errorf(
						"cannot split explicit-state plan at lane %d unit %d: batch boundary requires canonical base state payload",
						laneIndex,
						unitIndexInLane,
					)
				}
			}
			unitIndex++
		}
	}
	return nil
}

func canHeaderUnitStartIndependentExplicitStateBatch(unitIndexInLane int, unitHeader *ExplicitStateHeaderUnit) bool {
	if unitHeader == nil {
		return false
	}
	if unitHeader.BaseState == nil {
		return unitIndexInLane == 0
	}
	return hasCanonicalExplicitStatePayload(unitHeader.BaseState)
}

func validateExplicitStateBaseStateHeight(unitHeader *ExplicitStateHeaderUnit, baseState *ExplicitStateRef) error {
	if unitHeader == nil || baseState == nil || baseState.PrevHeight == nil || unitHeader.TrustedHeight == nil {
		return nil
	}
	if !baseState.PrevHeight.EQ(*unitHeader.TrustedHeight) {
		return fmt.Errorf(
			"explicit-state base_state prev_height mismatch: trusted_height=%s base_state_prev_height=%s",
			unitHeader.TrustedHeight.String(),
			baseState.PrevHeight.String(),
		)
	}
	return nil
}

func buildDeferredExplicitStateRef(
	anyHeader *codectypes.Any,
	cdc codectypes.AnyUnpacker,
) (*ExplicitStateRef, error) {
	trustedHeight, err := trustedHeightForExplicitState(anyHeader, cdc)
	if err != nil {
		return nil, err
	}
	ref := &ExplicitStateRef{}
	if trustedHeight != nil && !trustedHeight.IsZero() {
		h := *trustedHeight
		ref.PrevHeight = &h
	}
	return ref, nil
}

func (pr *Prover) queryExplicitStateRef(
	ctx context.Context,
	elcClientID string,
	anyHeader *codectypes.Any,
) (*ExplicitStateRef, error) {
	req := &explicitStateQueryClientRequest{ClientId: elcClientID}
	trustedHeight, err := trustedHeightForExplicitState(anyHeader, pr.codec)
	if err != nil {
		return nil, err
	}
	if trustedHeight != nil {
		req.Height = trustedHeight
	}

	pr.explicitStateQueryMu.Lock()
	defer pr.explicitStateQueryMu.Unlock()

	res, err := queryClientWithExplicitState(ctx, pr.lcpServiceClient, req)
	if err != nil {
		return nil, fmt.Errorf("failed to query ELC client state: %w", err)
	}
	if !res.Found {
		return nil, fmt.Errorf("client not found: client_id=%s", elcClientID)
	}

	var clientState ibcexported.ClientState
	if err := pr.codec.UnpackAny(res.ClientState, &clientState); err != nil {
		return nil, fmt.Errorf("failed to unpack ELC client state: %w", err)
	}

	var consensusState ibcexported.ConsensusState
	if err := pr.codec.UnpackAny(res.ConsensusState, &consensusState); err != nil {
		return nil, fmt.Errorf("failed to unpack ELC consensus state: %w", err)
	}

	ref, err := buildExplicitStateRefFromCanonicalState(clientState, consensusState)
	if err != nil {
		return nil, err
	}
	if trustedHeight != nil && !trustedHeight.IsZero() {
		h := *trustedHeight
		ref.PrevHeight = &h
	}
	return ref, nil
}

type explicitStateQueryClientRequest struct {
	ClientId string              `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Height   *clienttypes.Height `protobuf:"bytes,2,opt,name=height,proto3" json:"height,omitempty"`
}

func (m *explicitStateQueryClientRequest) Reset()         { *m = explicitStateQueryClientRequest{} }
func (m *explicitStateQueryClientRequest) String() string { return gogoproto.CompactTextString(m) }
func (*explicitStateQueryClientRequest) ProtoMessage()    {}

func queryClientWithExplicitState(
	ctx context.Context,
	client LCPServiceClient,
	req *explicitStateQueryClientRequest,
) (*elc.QueryClientResponse, error) {
	out := new(elc.QueryClientResponse)
	if err := client.conn.Invoke(ctx, queryClientMethod, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func trustedHeightForExplicitState(
	anyHeader *codectypes.Any,
	cdc codectypes.AnyUnpacker,
) (*clienttypes.Height, error) {
	if anyHeader == nil {
		return nil, nil
	}
	var clientMessage ibcexported.ClientMessage
	if cdc != nil {
		if err := cdc.UnpackAny(anyHeader, &clientMessage); err != nil {
			return nil, fmt.Errorf("failed to unpack explicit-state header: %w", err)
		}
	} else {
		switch anyHeader.TypeUrl {
		case "/ibc.lightclients.tendermint.v1.Header":
			var header tmclienttypes.Header
			if err := gogoproto.Unmarshal(anyHeader.Value, &header); err != nil {
				return nil, fmt.Errorf("failed to unmarshal tendermint explicit-state header: %w", err)
			}
			height := header.TrustedHeight
			return &height, nil
		default:
			return nil, nil
		}
	}
	switch header := clientMessage.(type) {
	case *tmclienttypes.Header:
		height := header.TrustedHeight
		return &height, nil
	default:
		return nil, nil
	}
}

func buildExplicitStateRefFromCanonicalState(
	clientState ibcexported.ClientState,
	consensusState ibcexported.ConsensusState,
) (*ExplicitStateRef, error) {
	ref := &ExplicitStateRef{}
	if clientState == nil {
		return nil, fmt.Errorf("client state must not be nil")
	}
	latestHeight, ok := clientState.GetLatestHeight().(clienttypes.Height)
	if !ok {
		return nil, fmt.Errorf("unsupported latest height type for explicit state ref: %T", clientState.GetLatestHeight())
	}
	if !latestHeight.IsZero() {
		h := latestHeight
		ref.PrevHeight = &h
	}

	// Extract PrevStateId when the consensus state carries one directly
	// (e.g. lcptypes.ConsensusState). For other prover-specific types
	// (Tendermint, Optimism, etc.) the prev_state_id is derived inside
	// LCP from Rust-side canonicalization, so we only pin the trusted
	// height and let LCP validate the observed transition.
	if cs, ok := consensusState.(*lcptypes.ConsensusState); ok && cs != nil && len(cs.StateId) > 0 {
		ref.PrevStateId = append([]byte(nil), cs.StateId...)
	}

	anyClientState, err := packClientStateForExplicitStatePayload(clientState)
	if err != nil {
		return nil, err
	}
	ref.ClientState = anyClientState

	anyConsensusState, err := clienttypes.PackConsensusState(consensusState)
	if err != nil {
		return nil, fmt.Errorf("failed to pack consensus state for explicit state ref: %w", err)
	}
	ref.ConsensusState = anyConsensusState
	return ref, nil
}

func computeExplicitStateID(
	clientState ibcexported.ClientState,
	consensusState ibcexported.ConsensusState,
) ([]byte, error) {
	anyClientState, err := packCanonicalClientStateForExplicitState(clientState)
	if err != nil {
		return nil, err
	}
	anyConsensusState, err := clienttypes.PackConsensusState(consensusState)
	if err != nil {
		return nil, fmt.Errorf("failed to pack consensus state for explicit state ref: %w", err)
	}
	clientBz, err := gogoproto.Marshal(anyClientState)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical client state any: %w", err)
	}
	consensusBz, err := gogoproto.Marshal(anyConsensusState)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal consensus state any: %w", err)
	}
	h := sha256.New()
	h.Write(clientBz)
	h.Write(consensusBz)
	return h.Sum(nil), nil
}

func packClientStateForExplicitStatePayload(
	clientState ibcexported.ClientState,
) (*codectypes.Any, error) {
	anyClientState, err := clienttypes.PackClientState(clientState)
	if err != nil {
		return nil, fmt.Errorf("failed to pack client state for explicit state payload: %w", err)
	}
	return anyClientState, nil
}

func packCanonicalClientStateForExplicitState(
	clientState ibcexported.ClientState,
) (*codectypes.Any, error) {
	switch cs := clientState.(type) {
	case *lcptypes.ClientState:
		anyClientState, err := clienttypes.PackClientState(cs)
		if err != nil {
			return nil, fmt.Errorf("failed to pack LCP client state for explicit state ref: %w", err)
		}
		return anyClientState, nil
	case *tmclienttypes.ClientState:
		canonical := tmclienttypes.NewClientState(
			cs.ChainId,
			cs.TrustLevel,
			cs.TrustingPeriod,
			cs.UnbondingPeriod,
			cs.MaxClockDrift,
			clienttypes.ZeroHeight(),
			cs.ProofSpecs,
			cs.UpgradePath,
		)
		canonical.AllowUpdateAfterExpiry = cs.AllowUpdateAfterExpiry
		canonical.AllowUpdateAfterMisbehaviour = cs.AllowUpdateAfterMisbehaviour
		anyClientState, err := clienttypes.PackClientState(canonical)
		if err != nil {
			return nil, fmt.Errorf("failed to pack tendermint client state for explicit state ref: %w", err)
		}
		return anyClientState, nil
	default:
		return nil, fmt.Errorf("unsupported client state type for explicit state ref: %T", clientState)
	}
}
