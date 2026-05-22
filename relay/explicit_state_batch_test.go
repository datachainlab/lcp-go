package relay

import (
	"io"
	"strings"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSendSpeculativeUpdateClientUnitRejectsOversizedUnitInit(t *testing.T) {
	stream := &recordingSpeculativeBatchStream{}
	err := sendSpeculativeUpdateClientUnit(stream, &SpeculativeUpdateClientUnit{
		UnitId: "unit-large",
		Update: &elc.MsgUpdateClient{
			ClientId: "client-0",
			Header: &codectypes.Any{
				TypeUrl: "header",
				Value:   []byte("h"),
			},
		},
		BaseState: &ExplicitStateRef{
			PrevHeight: &clienttypes.Height{RevisionHeight: 10},
			ClientState: &codectypes.Any{
				TypeUrl: "client",
				Value:   make([]byte, int(MaxSpeculativeBatchHeaderChunkSize)),
			},
			ConsensusState: &codectypes.Any{
				TypeUrl: "consensus",
				Value:   []byte("s"),
			},
		},
	}, DefaultMaxChunkSize)
	if err == nil {
		t.Fatal("expected oversized unit init error")
	}
	if !strings.Contains(err.Error(), `unit_id="unit-large"`) {
		t.Fatalf("expected unit id in error, got %v", err)
	}
	if len(stream.sent) != 0 {
		t.Fatalf("expected no stream sends after oversized unit init, got %d", len(stream.sent))
	}
}

func TestSpeculativeBatchStreamSenderEnrichesEOFWithServerStatus(t *testing.T) {
	stream := &recordingSpeculativeBatchStream{
		closeErr: status.Error(codes.ResourceExhausted, "speculative unit header payload too large"),
	}
	sender := &speculativeBatchStreamSender{stream: stream}

	err, closed := sender.enrichSendError(io.EOF)
	if !closed {
		t.Fatal("expected EOF enrichment to close the stream with CloseAndRecv")
	}
	if !strings.Contains(err.Error(), "server status after send failure") {
		t.Fatalf("expected enriched server status, got %v", err)
	}
	if !strings.Contains(err.Error(), "speculative unit header payload too large") {
		t.Fatalf("expected server detail in error, got %v", err)
	}
}

type recordingSpeculativeBatchStream struct {
	grpc.ClientStream
	sent               []*elc.MsgSpeculativeUpdateClientBatchStreamChunk
	sendErrAfter       int
	sendErr            error
	closeErr           error
	closeAndRecvCalled bool
	closeSendCalled    bool
}

func (s *recordingSpeculativeBatchStream) Send(m *elc.MsgSpeculativeUpdateClientBatchStreamChunk) error {
	if s.sendErrAfter > 0 && len(s.sent) >= s.sendErrAfter {
		return s.sendErr
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *recordingSpeculativeBatchStream) CloseAndRecv() (*elc.ExecuteSpeculativeUpdateClientBatchResponse, error) {
	s.closeAndRecvCalled = true
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	return &elc.ExecuteSpeculativeUpdateClientBatchResponse{}, nil
}

func (s *recordingSpeculativeBatchStream) CloseSend() error {
	s.closeSendCalled = true
	return nil
}
