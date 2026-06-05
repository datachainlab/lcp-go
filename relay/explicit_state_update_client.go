package relay

import (
	"context"
	"fmt"
	"strings"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

func (pr *Prover) shouldUseExplicitStateUpdateClient() bool {
	return pr.config.EnableExplicitStateUpdateClient
}

func isExplicitStateBaseStateMismatchError(err error) bool {
	if err == nil {
		return false
	}
	// LCP currently returns speculative batch failures as plain gRPC Aborted
	// status messages rather than typed error details:
	//
	//   Status::aborted(format!("{:?}: {}", e.kind, e.detail))
	//
	// The "BaseStateMismatch" substring is the Debug representation of
	// SpeculativeBatchFailureKind::BaseStateMismatch emitted by the LCP service
	// gRPC layer. The "canonical speculative base" substring is part of the
	// lower-level enclave/store validation error when the provided explicit
	// base client_state or consensus_state does not match the canonical LCP
	// store. Keep both checks until the LCP service exposes a typed gRPC error
	// detail or stable machine-readable error code for speculative failures.
	msg := err.Error()
	return strings.Contains(msg, "BaseStateMismatch") ||
		strings.Contains(msg, "canonical speculative base")
}

func (pr *Prover) queryLCPCanonicalExplicitStateBase(ctx context.Context, elcClientID string) (*ExplicitStateBase, error) {
	res, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{
		ClientId: elcClientID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query LCP ELC canonical state: client_id=%s %w", elcClientID, err)
	}
	if res == nil || !res.Found {
		return nil, fmt.Errorf("LCP ELC canonical state not found: client_id=%s", elcClientID)
	}
	if res.ClientState == nil {
		return nil, fmt.Errorf("LCP ELC canonical client_state is nil: client_id=%s", elcClientID)
	}
	if res.ConsensusState == nil {
		return nil, fmt.Errorf("LCP ELC canonical consensus_state is nil: client_id=%s", elcClientID)
	}
	var clientState exported.ClientState
	if err := pr.codec.UnpackAny(res.ClientState, &clientState); err != nil {
		return nil, fmt.Errorf("failed to unpack LCP ELC canonical client_state: client_id=%s %w", elcClientID, err)
	}
	height, ok := clientState.GetLatestHeight().(clienttypes.Height)
	if !ok {
		return nil, fmt.Errorf("unsupported LCP ELC canonical latest height type: client_id=%s height_type=%T", elcClientID, clientState.GetLatestHeight())
	}
	if height.IsZero() {
		return nil, fmt.Errorf("LCP ELC canonical latest height is zero: client_id=%s", elcClientID)
	}
	pr.getLogger().InfoContext(
		ctx,
		"queried LCP canonical explicit-state base",
		"elc_client_id", elcClientID,
		"base_height", height.String(),
		"client_state_type", res.ClientState.TypeUrl,
		"consensus_state_type", res.ConsensusState.TypeUrl,
	)
	return &ExplicitStateBase{
		Height:         height,
		ClientState:    cloneExplicitStateAny(res.ClientState),
		ConsensusState: cloneExplicitStateAny(res.ConsensusState),
	}, nil
}

func cloneExplicitStateAny(any *codectypes.Any) *codectypes.Any {
	if any == nil {
		return nil
	}
	return &codectypes.Any{
		TypeUrl: any.TypeUrl,
		Value:   append([]byte(nil), any.Value...),
	}
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
) ([]*elcupdater_storage.UpdateClientResult, error) {
	var results []*elcupdater_storage.UpdateClientResult

	maxUnits := pr.config.GetMaxSpeculativeBatchUnitsPerRequest()
	maxBatchBytes := pr.config.GetMaxSpeculativeBatchBytesPerRequest()
	var sender *speculativeBatchStreamSender
	closed := true
	batchSigners := make([][]byte, 0, maxUnits)
	batchIndex := 0
	unitIndex := 0
	batchBytes := 0
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
		batchBytes = 0
		return nil
	}

	for item := range unitStream {
		sourceUnit, err := explicitStateSourceHeaderUnitFromStreamItemOrError(item, unitIndex)
		if err != nil {
			return nil, err
		}
		if !hasCanonicalExplicitStatePayload(sourceUnit.BaseState) {
			return nil, fmt.Errorf(
				"explicit-state source header unit missing complete base state: index=%d unit_id=%q",
				unitIndex,
				buildSpeculativeUnitID(unitIndex),
			)
		}
		headerBytes := 0
		if sourceUnit.AnyHeader != nil {
			headerBytes = len(sourceUnit.AnyHeader.Value)
		}
		// Flush the in-flight batch before appending a unit whose header would
		// push aggregate streamed payload past the byte cap. This keeps peak
		// request memory bounded by batch boundary rather than
		// maxUnits * header_size.
		if sender != nil && headerBytes > 0 && batchBytes+headerBytes > maxBatchBytes {
			if err := flushBatch(); err != nil {
				return nil, err
			}
		}

		baseState := cloneExplicitStateRef(sourceUnit.BaseState)

		unitID := buildSpeculativeUnitID(unitIndex)
		update := &elc.MsgUpdateClient{
			ClientId:     elcClientID,
			Header:       sourceUnit.AnyHeader,
			IncludeState: includeState,
			Signer:       signer,
		}
		if err := openBatch(); err != nil {
			return nil, err
		}
		logExplicitStateUnitSend(ctx, pr, elcClientID, unitID, batchIndex, len(batchSigners), unitIndex, includeState, update)
		if err := sender.Send(&SpeculativeUpdateClientUnit{
			UnitId:    unitID,
			Update:    update,
			BaseState: baseState,
		}); err != nil {
			err, _ = sender.enrichSendError(err)
			return nil, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", len(batchSigners), unitID, err)
		}
		// The gRPC layer has already marshalled and queued the header bytes, so
		// release our in-process copy. Batch failures are surfaced as errors
		// instead of draining the source stream for serial fallback.
		sourceUnit.AnyHeader = nil
		update.Header = nil
		batchSigners = append(batchSigners, update.Signer)
		batchBytes += headerBytes
		unitIndex++

		if len(batchSigners) == maxUnits {
			if err := flushBatch(); err != nil {
				return nil, err
			}
		}
	}
	if err := flushBatch(); err != nil {
		return nil, err
	}
	return results, nil
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
