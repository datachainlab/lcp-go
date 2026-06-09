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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (pr *Prover) shouldUseExplicitStateUpdateClient() bool {
	return pr.config.EnableExplicitStateUpdateClient && pr.hasExplicitStateChunkProvider()
}

func (pr *Prover) hasExplicitStateChunkProvider() bool {
	_, ok := unwrapExplicitStateOriginProver(pr.originProver).(ExplicitStateChunkProvider)
	return ok
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
	// gRPC layer. The "stored speculative base" substring is part of the
	// lower-level enclave/store validation error when the provided explicit
	// base client_state or consensus_state does not match the base state stored
	// in LCP at the requested previous height. Keep both checks until the LCP
	// service exposes a typed gRPC error detail or stable machine-readable error
	// code for speculative failures.
	if status.Code(err) != codes.Aborted {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "BaseStateMismatch") ||
		strings.Contains(msg, "stored speculative base")
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
	var sender *speculativeBatchStreamSender
	closed := true
	batchUnitCount := 0
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
		if len(resp.Units) != batchUnitCount {
			return fmt.Errorf("unexpected speculative batch response shape: units=%d sent=%d", len(resp.Units), batchUnitCount)
		}
		for i, unit := range resp.Units {
			if unit == nil {
				return fmt.Errorf("unexpected speculative batch response unit at index %d", i)
			}
			results = append(results, &elcupdater_storage.UpdateClientResult{
				Message:   unit.Response.Message,
				Signature: unit.Response.Signature,
				Signer:    signer,
			})
		}
		sender = nil
		batchUnitCount = 0
		batchIndex++
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
				buildSpeculativeUnitID(batchIndex, batchUnitCount),
			)
		}
		unitID := buildSpeculativeUnitID(batchIndex, batchUnitCount)
		update := &elc.MsgUpdateClient{
			ClientId:     elcClientID,
			Header:       sourceUnit.AnyHeader,
			IncludeState: includeState,
			Signer:       signer,
		}
		if err := openBatch(); err != nil {
			return nil, err
		}
		logExplicitStateUnitSend(ctx, pr, elcClientID, unitID, batchIndex, batchUnitCount, unitIndex, includeState, update)
		if err := sender.Send(&SpeculativeUpdateClientUnit{
			UnitId:    unitID,
			Update:    update,
			BaseState: sourceUnit.BaseState,
		}); err != nil {
			err, _ = sender.enrichSendError(err)
			return nil, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", batchUnitCount, unitID, err)
		}
		// The gRPC layer has already marshalled and queued the header bytes, so
		// release our in-process copy. Batch failures are surfaced as errors
		// instead of draining the source stream for serial fallback.
		sourceUnit.AnyHeader = nil
		update.Header = nil
		batchUnitCount++
		unitIndex++

		if batchUnitCount == maxUnits {
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
