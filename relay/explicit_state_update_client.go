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

func disableExplicitStateUpdateClient() bool {
	v, ok := os.LookupEnv(envExplicitStateUpdateClient)
	if !ok {
		return false
	}
	switch v {
	case "0", "false", "FALSE", "False":
		return true
	default:
		return false
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
) ([]*elcupdater_storage.UpdateClientResult, []*ExplicitStateSourceHeaderUnit, error) {
	var results []*elcupdater_storage.UpdateClientResult
	var sourceHeaderUnits []*ExplicitStateSourceHeaderUnit

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
			return nil, sourceHeaderUnits, err
		}
		if sourceUnit.BaseState == nil {
			if err := flushBatch(); err != nil {
				return nil, sourceHeaderUnits, err
			}
			pendingUnits, err := collectCurrentAndRemainingExplicitStateSourceHeaderUnits(sourceUnit, unitStream, unitIndex)
			if err != nil {
				return nil, sourceHeaderUnits, err
			}
			return results, sourceHeaderUnits, &explicitStateSerialRestartError{
				pendingUnits: pendingUnits,
				reason:       fmt.Sprintf("explicit-state source unit %d missing base state; restart from this boundary", unitIndex),
			}
		}
		sourceHeaderUnits = append(sourceHeaderUnits, sourceUnit)
		if sourceUnit.AnyHeader == nil {
			return nil, sourceHeaderUnits, fmt.Errorf("explicit-state source header unit[%d] missing packed header", unitIndex)
		}
		if sourceUnit.BaseState == nil {
			return nil, sourceHeaderUnits, fmt.Errorf("explicit-state source header unit[%d] missing base state", unitIndex)
		}
		if err := validateExplicitStateBaseStateHeight(sourceUnit); err != nil {
			return nil, sourceHeaderUnits, err
		}

		baseState := cloneExplicitStateRef(sourceUnit.BaseState)

		unitID := buildSpeculativeUnitID(unitIndex)
		update := &elc.MsgUpdateClient{
			ClientId:     elcClientID,
			Header:       sourceUnit.AnyHeader,
			IncludeState: includeState,
			Signer:       signer,
		}
		if sender == nil && unitIndex > 0 && !hasCanonicalExplicitStatePayload(baseState) {
			return nil, sourceHeaderUnits, fmt.Errorf(
				"cannot split explicit-state batch at unit %s: missing base state payload",
				unitID,
			)
		}

		if err := openBatch(); err != nil {
			return nil, sourceHeaderUnits, err
		}
		logExplicitStateUnitSend(ctx, pr, elcClientID, unitID, batchIndex, len(batchSigners), unitIndex, includeState, update)
		if err := sender.Send(&SpeculativeUpdateClientUnit{
			UnitId:    unitID,
			Update:    update,
			BaseState: baseState,
		}); err != nil {
			err, _ = sender.enrichSendError(err)
			return nil, sourceHeaderUnits, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", len(batchSigners), unitID, err)
		}
		batchSigners = append(batchSigners, update.Signer)
		unitIndex++

		if len(batchSigners) == maxUnits {
			if err := flushBatch(); err != nil {
				return nil, sourceHeaderUnits, err
			}
		}
	}
	if err := flushBatch(); err != nil {
		return nil, sourceHeaderUnits, err
	}
	return results, sourceHeaderUnits, nil
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
	headerSHA256 := ""
	if update != nil && update.Header != nil {
		headerBytes = len(update.Header.Value)
		headerHash := sha256.Sum256(update.Header.Value)
		headerSHA256 = fmt.Sprintf("%x", headerHash)
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
		"header_sha256", headerSHA256,
	)
}

func validateExplicitStateBaseStateHeight(sourceUnit *ExplicitStateSourceHeaderUnit) error {
	if sourceUnit == nil || sourceUnit.BaseState == nil || sourceUnit.BaseState.PrevHeight == nil || sourceUnit.TrustedHeight == nil {
		return nil
	}
	if !sourceUnit.BaseState.PrevHeight.EQ(*sourceUnit.TrustedHeight) {
		return fmt.Errorf(
			"explicit-state base_state prev_height mismatch: trusted_height=%s base_state_prev_height=%s",
			sourceUnit.TrustedHeight.String(),
			sourceUnit.BaseState.PrevHeight.String(),
		)
	}
	return nil
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
