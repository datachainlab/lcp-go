package relay

import (
	"context"
	"errors"
	"fmt"
	"io"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
)

func executeSpeculativeUpdateClientPlannedUnitsStream(
	ctx context.Context,
	client LCPServiceClient,
	clientID string,
	units []*ExplicitStatePlannedUnit,
	chunkSize uint32,
) (*ExecuteSpeculativeUpdateClientBatchResponse, error) {
	sender, err := openSpeculativeUpdateClientBatchStream(ctx, client, clientID, chunkSize)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = sender.CloseSend()
		}
	}()
	for i, plannedUnit := range units {
		if plannedUnit == nil {
			return nil, fmt.Errorf("failed to prepare speculative batch unit: index=%d, planned unit must not be nil", i)
		}
		unit := &SpeculativeUpdateClientUnit{
			UnitId:    plannedUnit.UnitID,
			Update:    plannedUnit.Update,
			BaseState: plannedUnit.BaseState,
		}
		if err := sender.Send(unit); err != nil {
			var closedByRecv bool
			err, closedByRecv = sender.enrichSendError(err)
			if closedByRecv {
				closed = true
			}
			return nil, fmt.Errorf("failed to send speculative batch unit: index=%d unit_id=%q, %w", i, unitIDForError(unit), err)
		}
	}
	resp, err := sender.CloseAndRecv()
	closed = true
	return resp, err
}

type speculativeBatchStreamSender struct {
	stream    elc.Msg_SpeculativeUpdateClientBatchStreamClient
	chunkSize uint32
	count     int
}

func openSpeculativeUpdateClientBatchStream(
	ctx context.Context,
	client LCPServiceClient,
	clientID string,
	chunkSize uint32,
) (*speculativeBatchStreamSender, error) {
	if err := validateSpeculativeBatchStreamChunkSize(chunkSize); err != nil {
		return nil, err
	}
	stream, err := client.SpeculativeUpdateClientBatchStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call SpeculativeUpdateClientBatchStream: %w", err)
	}
	if err := stream.Send(&elc.MsgSpeculativeUpdateClientBatchStreamChunk{
		Chunk: &elc.MsgSpeculativeUpdateClientBatchStreamChunk_Init{
			Init: &elc.SpeculativeUpdateClientBatchStreamInit{
				ClientId: clientID,
			},
		},
	}); err != nil {
		_ = stream.CloseSend()
		return nil, fmt.Errorf("failed to send speculative batch init: %w", err)
	}
	return &speculativeBatchStreamSender{
		stream:    stream,
		chunkSize: chunkSize,
	}, nil
}

func (s *speculativeBatchStreamSender) Send(unit *SpeculativeUpdateClientUnit) error {
	if s == nil || s.stream == nil {
		return fmt.Errorf("speculative batch stream is not open")
	}
	if err := sendSpeculativeUpdateClientUnit(s.stream, unit, s.chunkSize); err != nil {
		return err
	}
	s.count++
	return nil
}

func (s *speculativeBatchStreamSender) CloseAndRecv() (*ExecuteSpeculativeUpdateClientBatchResponse, error) {
	if s == nil || s.stream == nil {
		return nil, fmt.Errorf("speculative batch stream is not open")
	}
	if err := s.stream.Send(&elc.MsgSpeculativeUpdateClientBatchStreamChunk{
		Chunk: &elc.MsgSpeculativeUpdateClientBatchStreamChunk_BatchEnd{
			BatchEnd: &elc.SpeculativeUpdateClientBatchEnd{},
		},
	}); err != nil {
		err, _ = s.enrichSendError(err)
		return nil, fmt.Errorf("failed to send speculative batch end: %w", err)
	}
	return s.recvCloseStatus()
}

func (s *speculativeBatchStreamSender) recvCloseStatus() (*ExecuteSpeculativeUpdateClientBatchResponse, error) {
	if s == nil || s.stream == nil {
		return nil, fmt.Errorf("speculative batch stream is not open")
	}
	resp, err := s.stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *speculativeBatchStreamSender) enrichSendError(sendErr error) (error, bool) {
	if !errors.Is(sendErr, io.EOF) {
		return sendErr, false
	}
	_, closeErr := s.recvCloseStatus()
	if closeErr == nil {
		return sendErr, true
	}
	return fmt.Errorf("%w; server status after send failure: %v", sendErr, closeErr), true
}

func (s *speculativeBatchStreamSender) CloseSend() error {
	if s == nil || s.stream == nil {
		return nil
	}
	return s.stream.CloseSend()
}

func sendSpeculativeUpdateClientUnit(
	stream elc.Msg_SpeculativeUpdateClientBatchStreamClient,
	unit *SpeculativeUpdateClientUnit,
	chunkSize uint32,
) error {
	if unit == nil {
		return fmt.Errorf("unit must not be nil")
	}
	if unit.Update == nil {
		return fmt.Errorf("unit update must not be nil")
	}
	if unit.Update.Header == nil {
		return fmt.Errorf("unit update header must not be nil")
	}
	if len(unit.Update.Header.Value) == 0 {
		return fmt.Errorf("unit update header value must not be empty")
	}
	if err := validateSpeculativeBatchStreamChunkSize(chunkSize); err != nil {
		return err
	}
	baseState := cloneExplicitStateRef(unit.BaseState)
	if baseState == nil {
		return fmt.Errorf("unit base_state must not be nil")
	}

	unitInitChunk := &elc.MsgSpeculativeUpdateClientBatchStreamChunk{
		Chunk: &elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitInit{
			UnitInit: &elc.SpeculativeUpdateClientUnitInit{
				UnitId:       unit.UnitId,
				TypeUrl:      unit.Update.Header.TypeUrl,
				IncludeState: unit.Update.IncludeState,
				Signer:       append([]byte(nil), unit.Update.Signer...),
				BaseState:    *baseState,
			},
		},
	}
	if size := proto.Size(unitInitChunk); size > MaxSpeculativeBatchHeaderChunkSize {
		return fmt.Errorf(
			"unit init chunk exceeds max speculative batch stream chunk size: unit_id=%q size=%d max=%d",
			unit.UnitId,
			size,
			MaxSpeculativeBatchHeaderChunkSize,
		)
	}
	if err := stream.Send(unitInitChunk); err != nil {
		return fmt.Errorf("failed to send unit init: %w", err)
	}

	chunks, err := splitBytes(unit.Update.Header.Value, chunkSize)
	if err != nil {
		return fmt.Errorf("failed to split unit header: %w", err)
	}
	for i, chunk := range chunks {
		if err := stream.Send(&elc.MsgSpeculativeUpdateClientBatchStreamChunk{
			Chunk: &elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitHeaderChunk{
				UnitHeaderChunk: &elc.SpeculativeUpdateClientUnitHeaderChunk{
					UnitId: unit.UnitId,
					Data:   chunk,
				},
			},
		}); err != nil {
			return fmt.Errorf("failed to send unit header chunk: index=%d, %w", i, err)
		}
	}

	if err := stream.Send(&elc.MsgSpeculativeUpdateClientBatchStreamChunk{
		Chunk: &elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitEnd{
			UnitEnd: &elc.SpeculativeUpdateClientUnitEnd{
				UnitId: unit.UnitId,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send unit end: %w", err)
	}
	return nil
}

func validateSpeculativeBatchStreamChunkSize(chunkSize uint32) error {
	if chunkSize == 0 {
		return fmt.Errorf("chunk size must be greater than 0")
	}
	if chunkSize > MaxSpeculativeBatchHeaderChunkSize {
		return fmt.Errorf("chunk size must be less than or equal to %d", MaxSpeculativeBatchHeaderChunkSize)
	}
	return nil
}

func unitIDForError(unit *SpeculativeUpdateClientUnit) string {
	if unit == nil {
		return ""
	}
	return unit.UnitId
}

func cloneExplicitStateRef(ref *ExplicitStateRef) *ExplicitStateRef {
	if ref == nil {
		return nil
	}
	var prevHeight *clienttypes.Height
	if ref.PrevHeight != nil {
		h := *ref.PrevHeight
		prevHeight = &h
	}
	return &ExplicitStateRef{
		PrevHeight:     prevHeight,
		PrevStateId:    append([]byte(nil), ref.PrevStateId...),
		ClientState:    cloneAny(ref.ClientState),
		ConsensusState: cloneAny(ref.ConsensusState),
	}
}

func cloneAny(any *codectypes.Any) *codectypes.Any {
	if any == nil {
		return nil
	}
	return &codectypes.Any{
		TypeUrl: any.TypeUrl,
		Value:   append([]byte(nil), any.Value...),
	}
}

func buildLinearSpeculativeUpdateClientBatch(
	clientID string,
	updates []*elc.MsgUpdateClient,
	baseStates []*ExplicitStateRef,
) (*ExecuteSpeculativeUpdateClientBatchRequest, error) {
	plan, err := newLinearExplicitStateUpdatePlan(clientID, updates, baseStates)
	if err != nil {
		return nil, err
	}
	return plan.buildRequest(), nil
}

func buildLaneSpeculativeUpdateClientBatch(
	clientID string,
	updateLanes [][]*elc.MsgUpdateClient,
	baseStateLanes [][]*ExplicitStateRef,
) (*ExecuteSpeculativeUpdateClientBatchRequest, error) {
	plan, err := newLaneExplicitStateUpdatePlan(clientID, updateLanes, baseStateLanes)
	if err != nil {
		return nil, err
	}
	return plan.buildRequest(), nil
}

func buildSpeculativeUnitID(i int) string {
	return fmt.Sprintf("unit-%04d", i)
}
