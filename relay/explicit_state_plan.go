package relay

import (
	"context"
	"fmt"
	"slices"

	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

const maxSpeculativeBatchUnitsPerRequest = 64

type ExplicitStatePlannedUnit struct {
	UnitID        string
	Update        *elc.MsgUpdateClient
	BaseState     *ExplicitStateRef
	DependencyIDs []string
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
		for _, dep := range unit.DependencyIDs {
			if _, ok := seen[dep]; !ok {
				return nil, fmt.Errorf("unit[%d] depends on unknown or non-preceding unit: %s", i, dep)
			}
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
		var prevUnitID string
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
			if prevUnitID != "" {
				unit.DependencyIDs = []string{prevUnitID}
			}
			units = append(units, unit)
			prevUnitID = unit.UnitID
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
			UnitId:        unit.UnitID,
			Update:        unit.Update,
			BaseState:     unit.BaseState,
			DependencyIds: append([]string(nil), unit.DependencyIDs...),
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

		batchUnitIDs := make(map[string]struct{}, end-start)
		for _, unit := range p.Units[start:end] {
			batchUnitIDs[unit.UnitID] = struct{}{}
		}

		units := make([]*ExplicitStatePlannedUnit, 0, end-start)
		for _, unit := range p.Units[start:end] {
			deps := make([]string, 0, len(unit.DependencyIDs))
			for _, dep := range unit.DependencyIDs {
				if _, ok := batchUnitIDs[dep]; ok {
					deps = append(deps, dep)
				}
			}
			units = append(units, &ExplicitStatePlannedUnit{
				UnitID:        unit.UnitID,
				Update:        unit.Update,
				BaseState:     cloneExplicitStateRef(unit.BaseState),
				DependencyIDs: deps,
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
	if unit == nil || unit.BaseState == nil {
		return false
	}
	return unit.BaseState.ClientState != nil && unit.BaseState.ConsensusState != nil
}

func (pr *Prover) executeExplicitStateUpdatePlan(
	ctx context.Context,
	plan *ExplicitStateUpdatePlan,
) ([]*elcupdater_storage.UpdateClientResult, error) {
	batches, err := plan.splitIntoExecutableBatches(maxSpeculativeBatchUnitsPerRequest)
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
			"batch_limit", maxSpeculativeBatchUnitsPerRequest,
		)
	}

	results := make([]*elcupdater_storage.UpdateClientResult, 0, len(plan.Units))
	for batchIndex, batch := range batches {
		req := batch.buildRequest()
		pr.getLogger().InfoContext(
			ctx,
			"invoke speculative update client batch",
			"client_id", req.ClientId,
			"num_units", len(req.Units),
			"batch_index", batchIndex,
			"num_batches", len(batches),
		)
		resp, err := executeSpeculativeUpdateClientBatchStream(ctx, pr.lcpServiceClient, req)
		if err != nil {
			return nil, fmt.Errorf("failed explicit-state update client batch: %w", err)
		}
		if len(resp.Units) != len(batch.Units) {
			return nil, fmt.Errorf("unexpected speculative batch response shape: units=%d plan=%d", len(resp.Units), len(batch.Units))
		}
		for i, unit := range resp.Units {
			if unit == nil || unit.Response == nil {
				return nil, fmt.Errorf("unexpected speculative batch response unit at index %d", i)
			}
			results = append(results, &elcupdater_storage.UpdateClientResult{
				Message:   unit.Response.Message,
				Signature: unit.Response.Signature,
				Signer:    batch.Units[i].Update.Signer,
			})
		}
	}
	return results, nil
}
