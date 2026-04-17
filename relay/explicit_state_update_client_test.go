package relay

import (
	"context"
	"reflect"
	"testing"
	"time"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type fakeExplicitStateCounterpartyQuerier struct {
	clientStateHeight clienttypes.Height
}

func (q fakeExplicitStateCounterpartyQuerier) LatestHeight(context.Context) (ibcexported.Height, error) {
	return q.clientStateHeight, nil
}

func (q fakeExplicitStateCounterpartyQuerier) QueryClientState(core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
	anyClientState, err := clienttypes.PackClientState(&tmclienttypes.ClientState{
		LatestHeight: q.clientStateHeight,
	})
	if err != nil {
		return nil, err
	}
	return &clienttypes.QueryClientStateResponse{ClientState: anyClientState}, nil
}

type fakeExplicitStateTMHeaderProvider struct{}

func (fakeExplicitStateTMHeaderProvider) UpdateLightClient(_ context.Context, height int64) (*tmclienttypes.Header, error) {
	return &tmclienttypes.Header{
		TrustedHeight: clienttypes.Height{RevisionHeight: uint64(height - 1)},
		SignedHeader:  &tmproto.SignedHeader{Header: &tmproto.Header{Height: height}},
		ValidatorSet:  &tmproto.ValidatorSet{},
	}, nil
}

type fakeExplicitStateTMValsetQuerier struct{}

func (fakeExplicitStateTMValsetQuerier) QueryValsetAtHeight(_ context.Context, _ clienttypes.Height) (*tmproto.ValidatorSet, error) {
	return &tmproto.ValidatorSet{}, nil
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
	if len(lanes) != 2 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 1 || len(lanes[1]) != 1 {
		t.Fatalf("unexpected lane widths: %#v", lanes)
	}
}

func TestPlanExplicitStateHeaderLanesAutoSelectsSingleHeaderForEmbeddedBaseState(t *testing.T) {
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
	if len(lanes) != 2 {
		t.Fatalf("unexpected lane count: %d", len(lanes))
	}
	if len(lanes[0]) != 1 || len(lanes[1]) != 1 {
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

func TestBuildExplicitStateUpdatePlanForHeaderLanesSharedTrustedHeight(t *testing.T) {
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

	pr := &Prover{}
	callCount := 0
	plan, err := pr.buildExplicitStateUpdatePlanForHeaderLanesWithResolver(
		context.Background(),
		lanes,
		"07-tendermint-0",
		false,
		[]byte("signer"),
		func(_ context.Context, elcClientID string, anyHeader *codectypes.Any) (*ExplicitStateRef, error) {
			callCount++
			if elcClientID != "07-tendermint-0" {
				t.Fatalf("unexpected elc client id: %s", elcClientID)
			}
			trustedHeight, err := trustedHeightForExplicitState(anyHeader, nil)
			if err != nil {
				t.Fatalf("trustedHeightForExplicitState() error = %v", err)
			}
			return &ExplicitStateRef{PrevHeight: trustedHeight}, nil
		},
	)
	if err != nil {
		t.Fatalf("buildExplicitStateUpdatePlanForHeaderLanesWithResolver() error = %v", err)
	}
	if got := plan.LaneWidths; len(got) != 1 || got[0] != 2 {
		t.Fatalf("unexpected lane widths: %v", got)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("unexpected plan unit count: %d", len(plan.Units))
	}
	if len(plan.Units[0].DependencyIDs) != 0 {
		t.Fatalf("unexpected dependencies: %v", plan.Units[0].DependencyIDs)
	}
	if len(plan.Units[1].DependencyIDs) != 1 || plan.Units[1].DependencyIDs[0] != "unit-0000" {
		t.Fatalf("unexpected chained dependencies: %v", plan.Units[1].DependencyIDs)
	}
	if plan.Units[0].BaseState == nil || plan.Units[0].BaseState.PrevHeight == nil || plan.Units[0].BaseState.PrevHeight.RevisionHeight != 10 {
		t.Fatalf("unexpected first base state: %#v", plan.Units[0].BaseState)
	}
	if plan.Units[1].BaseState == nil || plan.Units[1].BaseState.PrevHeight == nil || plan.Units[1].BaseState.PrevHeight.RevisionHeight != 10 {
		t.Fatalf("unexpected second base state: %#v", plan.Units[1].BaseState)
	}
	if plan.Units[1].BaseState.ClientState != nil || plan.Units[1].BaseState.ConsensusState != nil {
		t.Fatalf("unexpected deferred payload on second base state: %#v", plan.Units[1].BaseState)
	}
	if callCount != 1 {
		t.Fatalf("unexpected resolver call count: %d", callCount)
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

func TestCollectTendermintSharedTrustedSourceHeaderUnits(t *testing.T) {
	codec := core.MakeCodec()
	latestHeader := &tmclienttypes.Header{
		SignedHeader: &tmproto.SignedHeader{Header: &tmproto.Header{Height: 12}},
		ValidatorSet: &tmproto.ValidatorSet{},
	}
	units, ok, err := collectTendermintSharedTrustedSourceHeaderUnits(
		context.Background(),
		codec,
		fakeExplicitStateCounterpartyQuerier{
			clientStateHeight: clienttypes.Height{RevisionHeight: 10},
		},
		fakeExplicitStateTMHeaderProvider{},
		fakeExplicitStateTMValsetQuerier{},
		latestHeader,
		16,
	)
	if err != nil {
		t.Fatalf("collectTendermintSharedTrustedSourceHeaderUnits() error = %v", err)
	}
	if !ok {
		t.Fatal("expected tendermint multi-header collector to activate")
	}
	if len(units) != 2 {
		t.Fatalf("unexpected unit count: %d", len(units))
	}
	wantTrustedHeights := []uint64{10, 11}
	for i, unit := range units {
		if unit == nil || unit.TrustedHeight == nil || unit.TrustedHeight.RevisionHeight != wantTrustedHeights[i] {
			t.Fatalf("unexpected unit[%d] trusted height: %#v", i, unit)
		}
	}
}

func TestCollectTendermintSharedTrustedSourceHeaderUnitsRespectsLimit(t *testing.T) {
	codec := core.MakeCodec()
	latestHeader := &tmclienttypes.Header{
		SignedHeader: &tmproto.SignedHeader{Header: &tmproto.Header{Height: 20}},
		ValidatorSet: &tmproto.ValidatorSet{},
	}
	units, ok, err := collectTendermintSharedTrustedSourceHeaderUnits(
		context.Background(),
		codec,
		fakeExplicitStateCounterpartyQuerier{
			clientStateHeight: clienttypes.Height{RevisionHeight: 10},
		},
		fakeExplicitStateTMHeaderProvider{},
		fakeExplicitStateTMValsetQuerier{},
		latestHeader,
		4,
	)
	if err != nil {
		t.Fatalf("collectTendermintSharedTrustedSourceHeaderUnits() error = %v", err)
	}
	if !ok {
		t.Fatal("expected tendermint multi-header collector to activate")
	}
	var gotHeights []uint64
	for _, unit := range units {
		header, ok := unit.Header.(*tmclienttypes.Header)
		if !ok {
			t.Fatalf("unexpected header type: %T", unit.Header)
		}
		gotHeights = append(gotHeights, header.GetHeight().GetRevisionHeight())
	}
	wantHeights := []uint64{13, 15, 18, 20}
	if !reflect.DeepEqual(gotHeights, wantHeights) {
		t.Fatalf("unexpected collected heights: got=%v want=%v", gotHeights, wantHeights)
	}
}

func TestBuildExplicitStateTMTargetHeights(t *testing.T) {
	if got := buildExplicitStateTMTargetHeights(10, 10, 4); len(got) != 0 {
		t.Fatalf("expected empty targets, got %v", got)
	}
	if got := buildExplicitStateTMTargetHeights(10, 13, 4); !reflect.DeepEqual(got, []uint64{11, 12, 13}) {
		t.Fatalf("unexpected short-range targets: %v", got)
	}
	if got := buildExplicitStateTMTargetHeights(10, 20, 4); !reflect.DeepEqual(got, []uint64{13, 15, 18, 20}) {
		t.Fatalf("unexpected capped targets: %v", got)
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
