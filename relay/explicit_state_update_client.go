package relay

import (
	"context"
	"fmt"

	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

func (pr *Prover) shouldUseExplicitStateUpdateClient() bool {
	return !pr.config.DisableExplicitStateUpdateClient
}

func hasCanonicalExplicitStatePayload(baseState *ExplicitStateRef) bool {
	return baseState != nil &&
		baseState.PrevHeight != nil &&
		baseState.ClientState != nil &&
		baseState.ConsensusState != nil
}

func (pr *Prover) executeExplicitStateSourceHeaderUnitStreamWithResolver(
	ctx context.Context,
	unitStream <-chan *ExplicitStateSourceHeaderUnitOrError,
	elcClientID string,
	includeState bool,
	signer []byte,
) ([]*elcupdater_storage.UpdateClientResult, []*ExplicitStateSourceHeaderUnit, error) {
	var results []*elcupdater_storage.UpdateClientResult
	var fallbackUnits []*ExplicitStateSourceHeaderUnit

	maxUnits := pr.config.GetMaxSpeculativeBatchUnitsPerRequest()
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
		pr.getLogger().InfoContext(
			ctx,
			"invoke speculative update client batch",
			"client_id", elcClientID,
			"batch_index", batchIndex,
			"batch_unit_limit", maxUnits,
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
			return fmt.Errorf("unexpected speculative batch response shape: units=%d sent=%d", len(resp.Units), len(batchSigners))
		}
		for i, unit := range resp.Units {
			if unit == nil {
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

	for item := range unitStream {
		sourceUnit, err := explicitStateSourceHeaderUnitFromStreamItemOrError(item, unitIndex)
		if err != nil {
			return nil, fallbackUnits, err
		}
		if sourceUnit.BaseState == nil {
			fallbackUnits = append(fallbackUnits, sourceUnit)
			if err := flushBatch(); err != nil {
				return results, fallbackUnits, err
			}
			serialResults, err := pr.executeELCUpdateHeaderUnits(
				ctx,
				[]*ExplicitStateSourceHeaderUnit{sourceUnit},
				elcClientID,
				includeState,
				signer,
			)
			if err != nil {
				return results, fallbackUnits, err
			}
			results = append(results, serialResults...)
			fallbackUnits = fallbackUnits[:0]
			unitIndex++
			continue
		}
		fallbackUnits = append(fallbackUnits, sourceUnit)
		baseState := cloneExplicitStateRef(sourceUnit.BaseState)

		unitID := buildSpeculativeUnitID(unitIndex)
		update := &elc.MsgUpdateClient{
			ClientId:     elcClientID,
			Header:       sourceUnit.AnyHeader,
			IncludeState: includeState,
			Signer:       signer,
		}
		if sender == nil && unitIndex > 0 && !hasCanonicalExplicitStatePayload(baseState) {
			return results, fallbackUnits, fmt.Errorf(
				"cannot split explicit-state batch at unit %s: missing base state payload",
				unitID,
			)
		}

		if err := openBatch(); err != nil {
			return results, fallbackUnits, err
		}
		logExplicitStateUnitSend(ctx, pr, elcClientID, unitID, batchIndex, len(batchSigners), unitIndex, includeState, update)
		if err := sender.Send(&SpeculativeUpdateClientUnit{
			UnitId:    unitID,
			Update:    update,
			BaseState: baseState,
		}); err != nil {
			err, _ = sender.enrichSendError(err)
			return results, fallbackUnits, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", len(batchSigners), unitID, err)
		}
		batchSigners = append(batchSigners, update.Signer)
		unitIndex++

		if len(batchSigners) == maxUnits {
			if err := flushBatch(); err != nil {
				return results, fallbackUnits, err
			}
			fallbackUnits = fallbackUnits[:0]
		}
	}
	if err := flushBatch(); err != nil {
		return results, fallbackUnits, err
	}
	fallbackUnits = fallbackUnits[:0]
	return results, fallbackUnits, nil
}

func logExplicitStateUnitSend(
	ctx context.Context,
	pr *Prover,
	elcClientID string,
	unitID string,
	batchIndex int,
	batchUnitIndex int,
	unitIndex int,
	includeState bool,
	update *elc.MsgUpdateClient,
) {
	headerBytes := 0
	if update != nil && update.Header != nil {
		headerBytes = len(update.Header.Value)
	}
	pr.getLogger().InfoContext(
		ctx,
		"send speculative update client unit",
		"client_id", elcClientID,
		"unit_id", unitID,
		"batch_index", batchIndex,
		"batch_unit_index", batchUnitIndex,
		"unit_index", unitIndex,
		"include_state", includeState,
		"header_bytes", headerBytes,
	)
}
