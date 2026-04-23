package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

type ExplicitStatePlannedUnit struct {
	UnitID    string
	Update    *elc.MsgUpdateClient
	BaseState *ExplicitStateRef
}

type ExplicitStateUpdatePlan struct {
	ClientID   string
	Units      []*ExplicitStatePlannedUnit
	LaneWidths []int
}

func newExplicitStateUpdatePlan(
	clientID string,
	units []*ExplicitStatePlannedUnit,
) (*ExplicitStateUpdatePlan, error) {
	seen := make(map[string]struct{}, len(units))
	for i, unit := range units {
		if unit == nil {
			return nil, fmt.Errorf("unit[%d] must not be nil", i)
		}
		if unit.UnitID == "" {
			return nil, fmt.Errorf("unit[%d] must have non-empty unit_id", i)
		}
		if unit.Update == nil {
			return nil, fmt.Errorf("unit[%d] must have update", i)
		}
		if unit.BaseState == nil {
			return nil, fmt.Errorf("unit[%d] must have base_state", i)
		}
		if unit.Update.ClientId != clientID {
			return nil, fmt.Errorf("unit[%d] client_id mismatch: plan=%s unit=%s", i, clientID, unit.Update.ClientId)
		}
		if _, ok := seen[unit.UnitID]; ok {
			return nil, fmt.Errorf("duplicate unit_id in explicit-state plan: %s", unit.UnitID)
		}
		seen[unit.UnitID] = struct{}{}
	}
	return &ExplicitStateUpdatePlan{
		ClientID:   clientID,
		Units:      slices.Clone(units),
		LaneWidths: []int{len(units)},
	}, nil
}

func newLinearExplicitStateUpdatePlan(
	clientID string,
	updates []*elc.MsgUpdateClient,
	baseStates []*ExplicitStateRef,
) (*ExplicitStateUpdatePlan, error) {
	return newLaneExplicitStateUpdatePlan(clientID, [][]*elc.MsgUpdateClient{updates}, [][]*ExplicitStateRef{baseStates})
}

func newLaneExplicitStateUpdatePlan(
	clientID string,
	updateLanes [][]*elc.MsgUpdateClient,
	baseStateLanes [][]*ExplicitStateRef,
) (*ExplicitStateUpdatePlan, error) {
	if len(updateLanes) != len(baseStateLanes) {
		return nil, fmt.Errorf("update/base-state lane count mismatch: %d != %d", len(updateLanes), len(baseStateLanes))
	}
	var units []*ExplicitStatePlannedUnit
	unitIndex := 0
	for laneIndex, updates := range updateLanes {
		baseStates := baseStateLanes[laneIndex]
		if len(updates) != len(baseStates) {
			return nil, fmt.Errorf(
				"updates/base_states length mismatch in lane %d: %d != %d",
				laneIndex,
				len(updates),
				len(baseStates),
			)
		}
		for i, update := range updates {
			baseState := baseStates[i]
			if baseState == nil {
				baseState = &ExplicitStateRef{}
			}
			unit := &ExplicitStatePlannedUnit{
				UnitID:    buildSpeculativeUnitID(unitIndex),
				Update:    update,
				BaseState: baseState,
			}
			units = append(units, unit)
			unitIndex++
		}
	}
	plan, err := newExplicitStateUpdatePlan(clientID, units)
	if err != nil {
		return nil, err
	}
	plan.LaneWidths = make([]int, 0, len(updateLanes))
	for _, updates := range updateLanes {
		plan.LaneWidths = append(plan.LaneWidths, len(updates))
	}
	return plan, nil
}

func (p *ExplicitStateUpdatePlan) buildRequest() *ExecuteSpeculativeUpdateClientBatchRequest {
	req := &ExecuteSpeculativeUpdateClientBatchRequest{
		ClientId: p.ClientID,
		Units:    make([]*SpeculativeUpdateClientUnit, 0, len(p.Units)),
	}
	for _, unit := range p.Units {
		req.Units = append(req.Units, &SpeculativeUpdateClientUnit{
			UnitId:    unit.UnitID,
			Update:    unit.Update,
			BaseState: unit.BaseState,
		})
	}
	return req
}

func (p *ExplicitStateUpdatePlan) splitIntoExecutableBatches(maxUnits int) ([]*ExplicitStateUpdatePlan, error) {
	if maxUnits <= 0 || len(p.Units) <= maxUnits {
		return []*ExplicitStateUpdatePlan{p}, nil
	}

	var batches []*ExplicitStateUpdatePlan
	for start := 0; start < len(p.Units); start += maxUnits {
		end := min(start+maxUnits, len(p.Units))
		if start > 0 && !canStartIndependentExplicitStateBatch(p.Units[start]) {
			return nil, fmt.Errorf(
				"cannot split explicit-state plan at unit %s: missing base state payload",
				p.Units[start].UnitID,
			)
		}

		units := make([]*ExplicitStatePlannedUnit, 0, end-start)
		for _, unit := range p.Units[start:end] {
			units = append(units, &ExplicitStatePlannedUnit{
				UnitID:    unit.UnitID,
				Update:    unit.Update,
				BaseState: cloneExplicitStateRef(unit.BaseState),
			})
		}

		batch, err := newExplicitStateUpdatePlan(p.ClientID, units)
		if err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	return batches, nil
}

func canStartIndependentExplicitStateBatch(unit *ExplicitStatePlannedUnit) bool {
	if unit == nil {
		return false
	}
	return hasCanonicalExplicitStatePayload(unit.BaseState)
}

func hasCanonicalExplicitStatePayload(baseState *ExplicitStateRef) bool {
	return baseState != nil &&
		baseState.PrevHeight != nil &&
		baseState.ClientState != nil &&
		baseState.ConsensusState != nil
}

func (pr *Prover) executeExplicitStateUpdatePlan(
	ctx context.Context,
	plan *ExplicitStateUpdatePlan,
) ([]*elcupdater_storage.UpdateClientResult, error) {
	maxUnits := pr.config.GetMaxSpeculativeBatchUnitsPerRequest()
	batches, err := plan.splitIntoExecutableBatches(maxUnits)
	if err != nil {
		return nil, err
	}

	if len(batches) > 1 {
		pr.getLogger().InfoContext(
			ctx,
			"split speculative update client batch",
			"client_id", plan.ClientID,
			"num_units", len(plan.Units),
			"num_batches", len(batches),
			"batch_limit", maxUnits,
		)
	}

	results := make([]*elcupdater_storage.UpdateClientResult, 0, len(plan.Units))
	for batchIndex, batch := range batches {
		pr.getLogger().InfoContext(
			ctx,
			"invoke speculative update client batch",
			"client_id", batch.ClientID,
			"num_units", len(batch.Units),
			"batch_index", batchIndex,
			"num_batches", len(batches),
		)
		for i, unit := range batch.Units {
			logExplicitStateUnitInput(ctx, pr, batch.ClientID, unit, i, batchIndex, len(batches))
		}
		resp, err := executeSpeculativeUpdateClientPlannedUnitsStream(
			ctx,
			pr.lcpServiceClient,
			batch.ClientID,
			batch.Units,
			pr.config.GetMaxChunkSizeForUpdateClient(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed explicit-state update client batch: %w", err)
		}
		if len(resp.Units) != len(batch.Units) {
			return nil, fmt.Errorf("unexpected speculative batch response shape: units=%d plan=%d", len(resp.Units), len(batch.Units))
		}
		for i, unit := range resp.Units {
			if unit == nil {
				return nil, fmt.Errorf("unexpected speculative batch response unit at index %d", i)
			}
			logExplicitStateUnitObservedTransition(ctx, pr, batch, unit, i, batchIndex, len(batches))
			results = append(results, &elcupdater_storage.UpdateClientResult{
				Message:   unit.Response.Message,
				Signature: unit.Response.Signature,
				Signer:    batch.Units[i].Update.Signer,
			})
		}
	}
	return results, nil
}

func logExplicitStateUnitInput(
	ctx context.Context,
	pr *Prover,
	clientID string,
	unit *ExplicitStatePlannedUnit,
	unitIndex int,
	batchIndex int,
	numBatches int,
) {
	if unit == nil {
		return
	}
	baseState := unit.BaseState
	pr.getLogger().InfoContext(
		ctx,
		"explicit-state unit input base state",
		"client_id", clientID,
		"unit_id", unit.UnitID,
		"unit_index", unitIndex,
		"batch_index", batchIndex,
		"num_batches", numBatches,
		"input_prev_height", explicitStateHeightLogValue(explicitStateRefPrevHeight(baseState)),
		"input_prev_state_id", hexBytes(baseStatePrevStateID(baseState)),
		"input_has_complete_base_state", hasCanonicalExplicitStatePayload(baseState),
		"input_client_state_type_url", anyTypeURL(explicitStateRefClientState(baseState)),
		"input_client_state_bytes", anyValueLen(explicitStateRefClientState(baseState)),
		"input_consensus_state_type_url", anyTypeURL(explicitStateRefConsensusState(baseState)),
		"input_consensus_state_bytes", anyValueLen(explicitStateRefConsensusState(baseState)),
	)
}

func logExplicitStateUnitObservedTransition(
	ctx context.Context,
	pr *Prover,
	batch *ExplicitStateUpdatePlan,
	unitResult *StitchedSpeculativeUpdateClientUnitResult,
	unitIndex int,
	batchIndex int,
	numBatches int,
) {
	if batch == nil || unitIndex < 0 || unitIndex >= len(batch.Units) {
		return
	}
	plannedUnit := batch.Units[unitIndex]
	if plannedUnit == nil {
		return
	}
	transition := &unitResult.ObservedTransition
	var nextUnit *ExplicitStatePlannedUnit
	if unitIndex+1 < len(batch.Units) {
		nextUnit = batch.Units[unitIndex+1]
	}
	pr.getLogger().InfoContext(
		ctx,
		"explicit-state unit observed transition",
		"client_id", batch.ClientID,
		"unit_id", plannedUnit.UnitID,
		"unit_index", unitIndex,
		"batch_index", batchIndex,
		"num_batches", numBatches,
		"input_prev_height", explicitStateHeightLogValue(explicitStateRefPrevHeight(plannedUnit.BaseState)),
		"input_prev_state_id", hexBytes(baseStatePrevStateID(plannedUnit.BaseState)),
		"observed_prev_height", explicitStateHeightLogValue(observedPrevHeight(transition)),
		"observed_prev_state_id", hexBytes(observedPrevStateID(transition)),
		"observed_post_height", explicitStateHeightLogValue(observedPostHeight(transition)),
		"observed_post_state_id", hexBytes(observedPostStateID(transition)),
		"next_unit_id", explicitStateUnitID(nextUnit),
		"next_input_prev_height", explicitStateHeightLogValue(explicitStateRefPrevHeight(explicitStateUnitBaseState(nextUnit))),
		"next_input_prev_state_id", hexBytes(baseStatePrevStateID(explicitStateUnitBaseState(nextUnit))),
		"post_matches_next_input", observedPostMatchesNextInput(transition, nextUnit),
	)
}

func explicitStateRefPrevHeight(ref *ExplicitStateRef) *clienttypes.Height {
	if ref == nil {
		return nil
	}
	return ref.PrevHeight
}

func baseStatePrevStateID(ref *ExplicitStateRef) []byte {
	if ref == nil {
		return nil
	}
	return ref.PrevStateId
}

func explicitStateRefClientState(ref *ExplicitStateRef) *codectypes.Any {
	if ref == nil {
		return nil
	}
	return ref.ClientState
}

func explicitStateRefConsensusState(ref *ExplicitStateRef) *codectypes.Any {
	if ref == nil {
		return nil
	}
	return ref.ConsensusState
}

func explicitStateUnitBaseState(unit *ExplicitStatePlannedUnit) *ExplicitStateRef {
	if unit == nil {
		return nil
	}
	return unit.BaseState
}

func explicitStateUnitID(unit *ExplicitStatePlannedUnit) string {
	if unit == nil {
		return ""
	}
	return unit.UnitID
}

func observedPrevHeight(transition *ObservedStateTransition) *clienttypes.Height {
	if transition == nil {
		return nil
	}
	return transition.PrevHeight
}

func observedPostHeight(transition *ObservedStateTransition) *clienttypes.Height {
	if transition == nil {
		return nil
	}
	return &transition.PostHeight
}

func observedPrevStateID(transition *ObservedStateTransition) []byte {
	if transition == nil {
		return nil
	}
	return transition.PrevStateId
}

func observedPostStateID(transition *ObservedStateTransition) []byte {
	if transition == nil {
		return nil
	}
	return transition.PostStateId
}

func observedPostMatchesNextInput(transition *ObservedStateTransition, nextUnit *ExplicitStatePlannedUnit) bool {
	if transition == nil || nextUnit == nil || nextUnit.BaseState == nil {
		return false
	}
	return heightsEqual(&transition.PostHeight, nextUnit.BaseState.PrevHeight) &&
		bytes.Equal(transition.PostStateId, nextUnit.BaseState.PrevStateId)
}

func heightsEqual(a, b *clienttypes.Height) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.EQ(*b)
}

func explicitStateHeightLogValue(height *clienttypes.Height) string {
	if height == nil {
		return ""
	}
	return height.String()
}

func hexBytes(bz []byte) string {
	if len(bz) == 0 {
		return ""
	}
	return hex.EncodeToString(bz)
}

func anyTypeURL(any *codectypes.Any) string {
	if any == nil {
		return ""
	}
	return any.TypeUrl
}

func anyValueLen(any *codectypes.Any) int {
	if any == nil {
		return 0
	}
	return len(any.Value)
}
