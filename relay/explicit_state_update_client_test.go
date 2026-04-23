package relay

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type eofingSpeculativeMsgClient struct {
	elc.MsgClient
	stream *recordingSpeculativeBatchStream
}

func (c eofingSpeculativeMsgClient) SpeculativeUpdateClientBatchStream(
	context.Context,
	...grpc.CallOption,
) (elc.Msg_SpeculativeUpdateClientBatchStreamClient, error) {
	return c.stream, nil
}

func TestBuildExplicitStateRefFromCanonicalState(t *testing.T) {
	ref, err := buildExplicitStateRefFromCanonicalState(
		&lcptypes.ClientState{LatestHeight: clienttypes.Height{RevisionNumber: 0, RevisionHeight: 11}},
		&lcptypes.ConsensusState{StateId: []byte("post-0")},
	)
	if err != nil {
		t.Fatalf("buildExplicitStateRefFromCanonicalState() error = %v", err)
	}
	if ref.PrevHeight == nil || ref.PrevHeight.RevisionHeight != 11 {
		t.Fatalf("unexpected prev height: %+v", ref.PrevHeight)
	}
	if string(ref.PrevStateId) != "post-0" {
		t.Fatalf("unexpected prev state id: %q", string(ref.PrevStateId))
	}
}

func TestExecuteExplicitStateHeaderUnitsStreamClosesOpenStreamAndEnrichesEOF(t *testing.T) {
	stream := &recordingSpeculativeBatchStream{
		sendErrAfter: 2,
		sendErr:      io.EOF,
		closeErr:     status.Error(codes.ResourceExhausted, "speculative unit header payload too large"),
	}
	pr := &Prover{
		lcpServiceClient: LCPServiceClient{
			ELCMsgClient: eofingSpeculativeMsgClient{stream: stream},
		},
	}

	_, err := pr.executeExplicitStateHeaderUnitsStreamWithResolver(
		context.Background(),
		[]*ExplicitStateHeaderUnit{
			{Header: &codectypes.Any{TypeUrl: "header", Value: []byte("header")}},
		},
		"07-tendermint-11",
		false,
		[]byte("signer"),
		func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error) {
			return &ExplicitStateRef{
				ClientState:    &codectypes.Any{TypeUrl: "client", Value: []byte("client")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus", Value: []byte("consensus")},
			}, nil
		},
	)
	if err == nil {
		t.Fatal("expected send error")
	}
	if !strings.Contains(err.Error(), "server status after send failure") {
		t.Fatalf("expected enriched EOF status, got %v", err)
	}
	if !strings.Contains(err.Error(), "speculative unit header payload too large") {
		t.Fatalf("expected server status detail, got %v", err)
	}
	if !stream.closeAndRecvCalled {
		t.Fatal("expected EOF enrichment to call CloseAndRecv")
	}
	if !stream.closeSendCalled {
		t.Fatal("expected deferred CloseSend for open speculative stream")
	}
}

func TestBuildExplicitStateRefFromCanonicalStateZeroHeight(t *testing.T) {
	ref, err := buildExplicitStateRefFromCanonicalState(
		&lcptypes.ClientState{},
		&lcptypes.ConsensusState{},
	)
	if err != nil {
		t.Fatalf("buildExplicitStateRefFromCanonicalState() error = %v", err)
	}
	if ref.PrevHeight != nil {
		t.Fatalf("expected nil prev height for zero canonical height: %+v", ref.PrevHeight)
	}
	if len(ref.PrevStateId) != 0 {
		t.Fatalf("expected empty prev state id: %x", ref.PrevStateId)
	}
}

func TestBuildExplicitStateRefFromCanonicalStateTendermint(t *testing.T) {
	clientState := tmclienttypes.NewClientState(
		"ibc0",
		tmclienttypes.DefaultTrustLevel,
		14*24*time.Hour,
		21*24*time.Hour,
		10*time.Second,
		clienttypes.NewHeight(0, 21),
		nil,
		[]string{"upgrade", "upgradedIBCState"},
	)
	consensusState := tmclienttypes.NewConsensusState(
		time.Unix(1773717522, 0),
		commitmenttypes.NewMerkleRoot([]byte("apphash")),
		[]byte("next-validators"),
	)

	ref, err := buildExplicitStateRefFromCanonicalState(clientState, consensusState)
	if err != nil {
		t.Fatalf("buildExplicitStateRefFromCanonicalState() error = %v", err)
	}
	if ref.PrevHeight == nil || ref.PrevHeight.RevisionHeight != 21 {
		t.Fatalf("unexpected prev height: %+v", ref.PrevHeight)
	}
	if len(ref.PrevStateId) != 0 {
		t.Fatalf("expected tendermint explicit state ref to omit prev state id: %x", ref.PrevStateId)
	}
}

func TestBuildExplicitStateHeaderUnitsRejectsNilHeader(t *testing.T) {
	_, err := buildExplicitStateHeaderUnits([]*codectypes.Any{{TypeUrl: "header-0"}, nil})
	if err == nil {
		t.Fatal("expected nil header error, got nil")
	}
}

func TestBuildExplicitStateHeaderUnitsTrustedHeight(t *testing.T) {
	units, err := buildExplicitStateHeaderUnits([]*codectypes.Any{
		mustPackTMHeaderForExplicitStateTest(t, 17),
	})
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	if len(units) != 1 || units[0].TrustedHeight == nil || units[0].TrustedHeight.RevisionHeight != 17 {
		t.Fatalf("unexpected header units: %#v", units)
	}
}

func TestExtractAnyHeadersFromSourceUnitsRejectsMissingPackedHeader(t *testing.T) {
	_, err := extractAnyHeadersFromSourceUnits([]*ExplicitStateSourceHeaderUnit{{
		Header: &tmclienttypes.Header{},
	}})
	if err == nil {
		t.Fatal("expected missing packed header error")
	}
	if !strings.Contains(err.Error(), "missing packed header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustPackTMHeaderForExplicitStateTest(t *testing.T, trustedHeight uint64) *codectypes.Any {
	t.Helper()
	anyHeader, err := codectypes.NewAnyWithValue(&tmclienttypes.Header{
		TrustedHeight: clienttypes.Height{RevisionHeight: trustedHeight},
	})
	if err != nil {
		t.Fatalf("failed to pack tendermint header: %v", err)
	}
	return anyHeader
}
