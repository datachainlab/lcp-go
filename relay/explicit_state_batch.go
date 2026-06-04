package relay

import (
	"context"
	"errors"
	"fmt"
	"io"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	gogoproto "github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
)

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
	if !hasCanonicalExplicitStatePayload(unit.BaseState) {
		return fmt.Errorf("unit base_state must be complete")
	}
	baseState := cloneExplicitStateRef(unit.BaseState)

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
	if size := gogoproto.Size(unitInitChunk); size > DefaultMaxChunkSize {
		return fmt.Errorf(
			"unit init chunk exceeds max safe speculative batch stream chunk size: unit_id=%q size=%d max=%d",
			unit.UnitId,
			size,
			DefaultMaxChunkSize,
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
	return gogoproto.Clone(any).(*codectypes.Any)
}

func buildSpeculativeUnitID(i int) string {
	return fmt.Sprintf("unit-%d", i)
}
