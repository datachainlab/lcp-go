package relay

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
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

// ExplicitStateBaseDriftError indicates that the LCP canonical state has
// advanced past the on-chain committed state, so the explicit-state path
// cannot anchor a speculative batch at the on-chain base.
type ExplicitStateBaseDriftError struct {
	OnChainHeight   clienttypes.Height
	CanonicalHeight clienttypes.Height
}

func (e *ExplicitStateBaseDriftError) Error() string {
	return fmt.Sprintf(
		"LCP canonical state is ahead of the on-chain committed state: on_chain_height=%v lcp_canonical_height=%v",
		e.OnChainHeight, e.CanonicalHeight,
	)
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

// queryOnChainExplicitStateBaseWithFallback prefers the on-chain committed
// base. It falls back to the LCP canonical base only when the destination
// does not host an LCP client (e.g. test/mock configurations); query
// failures are returned as errors instead of silently weakening the base.
func (pr *Prover) queryOnChainExplicitStateBaseWithFallback(ctx context.Context, dstChain core.FinalityAwareChain, elcClientID string) (*ExplicitStateBase, error) {
	base, ok, err := pr.queryOnChainCommittedExplicitStateBase(ctx, dstChain, elcClientID)
	if err != nil {
		return nil, err
	}
	if ok {
		return base, nil
	}
	pr.getLogger().InfoContext(
		ctx,
		"on-chain LCP explicit-state base is unavailable; falling back to LCP canonical base",
		"elc_client_id", elcClientID,
	)
	return pr.queryLCPCanonicalExplicitStateBase(ctx, elcClientID)
}

// queryOnChainCommittedExplicitStateBase anchors the explicit-state base at
// the on-chain committed (height, state_id) and sources the base payload
// bytes from the LCP canonical store. The payload must be the canonical
// bytes verbatim: LCP's stitch-phase verification compares the supplied
// base against the stored canonical state byte-for-byte, and any payload
// re-encoded outside the enclave (e.g. rebuilt from chain queries) diverges
// from the enclave round-trip encoding. The on-chain state_id is kept as
// the witness binding the canonical payload to the committed state.
func (pr *Prover) queryOnChainCommittedExplicitStateBase(ctx context.Context, dstChain core.FinalityAwareChain, elcClientID string) (*ExplicitStateBase, bool, error) {
	if dstChain == nil {
		return nil, false, nil
	}
	queryHeight, err := dstChain.LatestHeight(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("failed to query destination latest height for explicit-state base: %w", err)
	}
	clientRes, err := dstChain.QueryClientState(core.NewQueryContext(ctx, queryHeight))
	if err != nil {
		return nil, true, fmt.Errorf("failed to query on-chain LCP client_state for explicit-state base: query_height=%v %w", queryHeight, err)
	}
	if clientRes == nil || clientRes.ClientState == nil {
		return nil, true, fmt.Errorf("on-chain LCP client_state is nil for explicit-state base: query_height=%v", queryHeight)
	}
	var clientState exported.ClientState
	if err := pr.codec.UnpackAny(clientRes.ClientState, &clientState); err != nil {
		return nil, true, fmt.Errorf("failed to unpack on-chain client_state for explicit-state base: query_height=%v %w", queryHeight, err)
	}
	lcpClientState, ok := clientState.(*lcptypes.ClientState)
	if !ok {
		return nil, false, nil
	}
	baseHeight := lcpClientState.LatestHeight
	if baseHeight.IsZero() {
		return nil, true, fmt.Errorf("on-chain LCP latest height is zero for explicit-state base: query_height=%v", queryHeight)
	}
	consensusRes, err := dstChain.QueryClientConsensusState(core.NewQueryContext(ctx, queryHeight), baseHeight)
	if err != nil {
		return nil, true, fmt.Errorf("failed to query on-chain LCP consensus_state for explicit-state base: query_height=%v base_height=%v %w", queryHeight, baseHeight, err)
	}
	if consensusRes == nil || consensusRes.ConsensusState == nil {
		return nil, true, fmt.Errorf("on-chain LCP consensus_state is nil for explicit-state base: query_height=%v base_height=%v", queryHeight, baseHeight)
	}
	var consensusState exported.ConsensusState
	if err := pr.codec.UnpackAny(consensusRes.ConsensusState, &consensusState); err != nil {
		return nil, true, fmt.Errorf("failed to unpack on-chain LCP consensus_state for explicit-state base: query_height=%v base_height=%v %w", queryHeight, baseHeight, err)
	}
	lcpConsensusState, ok := consensusState.(*lcptypes.ConsensusState)
	if !ok {
		return nil, true, fmt.Errorf("unexpected on-chain consensus_state type for explicit-state base: query_height=%v base_height=%v consensus_state_type=%T", queryHeight, baseHeight, consensusState)
	}
	if len(lcpConsensusState.StateId) == 0 {
		return nil, true, fmt.Errorf("on-chain LCP consensus_state state_id is empty for explicit-state base: query_height=%v base_height=%v", queryHeight, baseHeight)
	}
	canonicalBase, err := pr.queryLCPCanonicalExplicitStateBase(ctx, elcClientID)
	if err != nil {
		return nil, true, fmt.Errorf("failed to query LCP canonical payload for on-chain committed explicit-state base: base_height=%v %w", baseHeight, err)
	}
	if canonicalBase.Height.GetRevisionNumber() != baseHeight.GetRevisionNumber() ||
		canonicalBase.Height.GetRevisionHeight() != baseHeight.GetRevisionHeight() {
		// The canonical store only serves the latest payload, so a speculative
		// batch cannot be anchored at an earlier committed height (canonical
		// drifted ahead of the on-chain commitment, e.g. a prior updateELC
		// committed at the stitch but its UpdateClient message was never
		// submitted). Return a typed error so the caller can recover via the
		// serial path, which the enclave anchors at its stored consensus for
		// the on-chain height.
		return nil, true, &ExplicitStateBaseDriftError{
			OnChainHeight:   baseHeight,
			CanonicalHeight: canonicalBase.Height,
		}
	}
	pr.getLogger().InfoContext(
		ctx,
		"queried on-chain committed explicit-state base",
		"query_height", queryHeight.String(),
		"base_height", baseHeight.String(),
		"on_chain_state_id", fmt.Sprintf("0x%x", lcpConsensusState.StateId),
		"client_state_type", canonicalBase.ClientState.TypeUrl,
		"consensus_state_type", canonicalBase.ConsensusState.TypeUrl,
	)
	return &ExplicitStateBase{
		Height:         baseHeight,
		ClientState:    canonicalBase.ClientState,
		ConsensusState: canonicalBase.ConsensusState,
		StateId:        append([]byte(nil), lcpConsensusState.StateId...),
	}, true, nil
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

// bindFirstUnitToExplicitStateBase pins the first source unit to the queried
// explicit-state base so a provider/base divergence fails fast in the relayer
// with a precise error instead of a generic LCP-side BaseStateMismatch. When
// the base carries a committed state ID, it is threaded into the unit's
// prev_state_id so LCP additionally verifies that the enclave-observed
// transition anchors at exactly that state.
func bindFirstUnitToExplicitStateBase(unit *ExplicitStateSourceHeaderUnit, base *ExplicitStateBase) error {
	if base == nil {
		return nil
	}
	prevHeight := unit.BaseState.PrevHeight
	if prevHeight == nil || *prevHeight != base.Height {
		return fmt.Errorf(
			"first explicit-state unit base height mismatch: unit_prev_height=%v base_height=%v",
			prevHeight,
			base.Height,
		)
	}
	if len(base.StateId) == 0 {
		return nil
	}
	if len(unit.BaseState.PrevStateId) == 0 {
		boundBaseState := cloneExplicitStateRef(unit.BaseState)
		boundBaseState.PrevStateId = append([]byte(nil), base.StateId...)
		unit.BaseState = boundBaseState
		return nil
	}
	if !bytes.Equal(unit.BaseState.PrevStateId, base.StateId) {
		return fmt.Errorf(
			"first explicit-state unit prev_state_id mismatch: unit_prev_state_id=0x%x base_state_id=0x%x",
			unit.BaseState.PrevStateId,
			base.StateId,
		)
	}
	return nil
}

func (pr *Prover) executeExplicitStateSourceHeaderUnitStream(
	ctx context.Context,
	unitStream <-chan *ExplicitStateSourceHeaderUnitOrError,
	base *ExplicitStateBase,
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
		if unitIndex == 0 {
			if err := bindFirstUnitToExplicitStateBase(sourceUnit, base); err != nil {
				return nil, err
			}
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
			var streamClosed bool
			err, streamClosed = sender.enrichSendError(err)
			if streamClosed {
				closed = true
			}
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
