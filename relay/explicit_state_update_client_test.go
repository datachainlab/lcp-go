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

func TestExecuteExplicitStateHeaderLanesStreamClosesOpenStreamAndEnrichesEOF(t *testing.T) {
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

	_, err := pr.executeExplicitStateHeaderLanesStreamWithResolver(
		context.Background(),
		[][]*ExplicitStateHeaderUnit{{
			{Header: &codectypes.Any{TypeUrl: "header", Value: []byte("header")}},
		}},
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

func TestPlanConservativeExplicitStateHeaderLanes(t *testing.T) {
	headers := []*codectypes.Any{
		{TypeUrl: "header-0"},
		{TypeUrl: "header-1"},
	}
	units, err := buildExplicitStateHeaderUnits(headers)
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	lanes, err := planConservativeExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planConservativeExplicitStateHeaderLanes() error = %v", err)
	}
	if len(lanes) != 1 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 2 {
		t.Fatalf("unexpected lane width: %d", len(lanes[0]))
	}
	if lanes[0][0].Header != headers[0] || lanes[0][1].Header != headers[1] {
		t.Fatalf("unexpected lane contents: %#v", lanes[0])
	}
}

func TestPlanConservativeExplicitStateHeaderLanesEmpty(t *testing.T) {
	lanes, err := planConservativeExplicitStateHeaderLanes(nil)
	if err != nil {
		t.Fatalf("planConservativeExplicitStateHeaderLanes() error = %v", err)
	}
	if lanes != nil {
		t.Fatalf("expected nil lanes, got %#v", lanes)
	}
}

func TestPlanConservativeExplicitStateHeaderLanesRejectsNilHeader(t *testing.T) {
	_, err := buildExplicitStateHeaderUnits([]*codectypes.Any{{TypeUrl: "header-0"}, nil})
	if err == nil {
		t.Fatal("expected nil header error, got nil")
	}
}

func TestPlanExplicitStateHeaderLanesSingleHeader(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "single_header")
	headers := []*codectypes.Any{
		{TypeUrl: "header-0"},
		{TypeUrl: "header-1"},
	}
	units, err := buildExplicitStateHeaderUnits(headers)
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	lanes, err := planExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planExplicitStateHeaderLanes() error = %v", err)
	}
	if len(lanes) != 1 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 2 {
		t.Fatalf("unexpected lane widths: %#v", lanes)
	}
}

func TestPlanExplicitStateHeaderLanesSingleHeaderSplitsOnlyCompleteBaseState(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "single_header")
	completeBaseState := func(height uint64) *ExplicitStateRef {
		return &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: height},
			ClientState:    &codectypes.Any{TypeUrl: "client", Value: []byte("client")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus", Value: []byte("consensus")},
		}
	}
	units := []*ExplicitStateHeaderUnit{
		{
			Header:        &codectypes.Any{TypeUrl: "header-0"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
			BaseState:     completeBaseState(10),
		},
		{
			Header:        &codectypes.Any{TypeUrl: "header-1"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 11},
			BaseState: &ExplicitStateRef{
				PrevHeight: &clienttypes.Height{RevisionHeight: 11},
			},
		},
		{
			Header:        &codectypes.Any{TypeUrl: "header-2"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 12},
			BaseState:     completeBaseState(12),
		},
		{
			Header:        &codectypes.Any{TypeUrl: "header-3"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 13},
			BaseState:     completeBaseState(99),
		},
	}

	lanes, err := planExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planExplicitStateHeaderLanes() error = %v", err)
	}
	if got := explicitStateHeaderLaneWidths(lanes); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Fatalf("unexpected lane widths: %v", got)
	}
	if lanes[0][0] != units[0] || lanes[0][1] != units[1] || lanes[1][0] != units[2] || lanes[1][1] != units[3] {
		t.Fatalf("unexpected lane contents: %#v", lanes)
	}
}

func TestPlanExplicitStateHeaderLanesKeepsEmbeddedBaseStateUnitsOrderedByDefault(t *testing.T) {
	units := []*ExplicitStateHeaderUnit{
		{
			Header:        &codectypes.Any{TypeUrl: "header-0"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
			BaseState:     &ExplicitStateRef{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
		},
		{
			Header:        &codectypes.Any{TypeUrl: "header-1"},
			TrustedHeight: &clienttypes.Height{RevisionHeight: 11},
			BaseState:     &ExplicitStateRef{PrevHeight: &clienttypes.Height{RevisionHeight: 11}},
		},
	}
	lanes, err := planExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planExplicitStateHeaderLanes() error = %v", err)
	}
	if len(lanes) != 1 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 2 {
		t.Fatalf("unexpected lane widths: %#v", lanes)
	}
}

func TestPlanExplicitStateHeaderLanesSharedTrustedHeight(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "shared_trusted_height")
	headers := []*codectypes.Any{
		mustPackTMHeaderForExplicitStateTest(t, 10),
		mustPackTMHeaderForExplicitStateTest(t, 10),
	}
	units, err := buildExplicitStateHeaderUnits(headers)
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	lanes, err := planExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planExplicitStateHeaderLanes() error = %v", err)
	}
	if len(lanes) != 1 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 2 {
		t.Fatalf("unexpected lane widths: %#v", lanes)
	}
}

func TestPlanExplicitStateHeaderLanesSharedTrustedHeightFallbacksToConservative(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "shared_trusted_height")
	headers := []*codectypes.Any{
		mustPackTMHeaderForExplicitStateTest(t, 10),
		mustPackTMHeaderForExplicitStateTest(t, 11),
	}
	units, err := buildExplicitStateHeaderUnits(headers)
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	lanes, err := planExplicitStateHeaderLanes(units)
	if err != nil {
		t.Fatalf("planExplicitStateHeaderLanes() error = %v", err)
	}
	if len(lanes) != 1 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 2 {
		t.Fatalf("unexpected lane width: %d", len(lanes[0]))
	}
}

func TestPlanExplicitStateHeaderLanesRejectsUnknownStrategy(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "bad_strategy")
	units, err := buildExplicitStateHeaderUnits([]*codectypes.Any{{TypeUrl: "header-0"}})
	if err != nil {
		t.Fatalf("buildExplicitStateHeaderUnits() error = %v", err)
	}
	_, err = planExplicitStateHeaderLanes(units)
	if err == nil {
		t.Fatal("expected unknown strategy error, got nil")
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

func TestExplicitStateLaneLimitReason(t *testing.T) {
	t.Setenv(envExplicitStateLaneStrategy, "shared_trusted_height")
	if got := explicitStateLaneLimitReason(nil, nil); got != "no_source_headers" {
		t.Fatalf("unexpected empty-source reason: %s", got)
	}
	if got := explicitStateLaneLimitReason([]*ExplicitStateSourceHeaderUnit{{TrustedHeight: &clienttypes.Height{RevisionHeight: 10}}}, []int{1}); got != "single_source_header" {
		t.Fatalf("unexpected single-source reason: %s", got)
	}
	if got := explicitStateLaneLimitReason(
		[]*ExplicitStateSourceHeaderUnit{
			{TrustedHeight: &clienttypes.Height{RevisionHeight: 10}},
			{TrustedHeight: &clienttypes.Height{RevisionHeight: 11}},
		},
		[]int{2},
	); got != "mixed_trusted_height" {
		t.Fatalf("unexpected mixed trusted-height reason: %s", got)
	}
	if got := explicitStateLaneLimitReason(
		[]*ExplicitStateSourceHeaderUnit{
			{AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10), TrustedHeight: &clienttypes.Height{RevisionHeight: 10}},
			{AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10), TrustedHeight: &clienttypes.Height{RevisionHeight: 10}},
		},
		[]int{2},
	); got != "shared_write_domain" {
		t.Fatalf("unexpected shared-write-domain reason: %s", got)
	}

	t.Setenv(envExplicitStateLaneStrategy, "conservative")
	if got := explicitStateLaneLimitReason(
		[]*ExplicitStateSourceHeaderUnit{
			{AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10), TrustedHeight: &clienttypes.Height{RevisionHeight: 10}},
			{AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10), TrustedHeight: &clienttypes.Height{RevisionHeight: 10}},
		},
		[]int{2},
	); got != "conservative_strategy" {
		t.Fatalf("unexpected conservative reason: %s", got)
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
