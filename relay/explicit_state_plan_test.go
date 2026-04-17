package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/datachainlab/lcp-go/relay/elcupdater"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/core"
	ylog "github.com/hyperledger-labs/yui-relayer/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type explicitStateBatchTestService interface {
	SpeculativeUpdateClientBatchStream(elc.Msg_SpeculativeUpdateClientBatchStreamServer) error
}

type explicitStateFallbackTestServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	updateCalls int
}

func (s *explicitStateFallbackTestServer) UpdateClientStream(stream elc.Msg_UpdateClientStreamServer) error {
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			s.updateCalls++
			return stream.SendAndClose(&elc.MsgUpdateClientResponse{
				Message:   mustMakeExplicitStateTestHeaderedUpdateStateMessage(uint64(10+s.updateCalls), byte(s.updateCalls)),
				Signature: []byte(fmt.Sprintf("sig-%d", s.updateCalls-1)),
			})
		}
		if err != nil {
			return err
		}
		if chunk == nil {
			return fmt.Errorf("received nil update client stream chunk")
		}
	}
}

type explicitStateBatchTestServer struct {
	elc.UnimplementedMsgServer
	captured **ExecuteSpeculativeUpdateClientBatchRequest
}

func (s explicitStateBatchTestServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	*s.captured = req
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units: []*elc.StitchedSpeculativeUpdateClientUnitResult{
			{Response: elc.MsgUpdateClientResponse{Message: []byte("msg-0"), Signature: []byte("sig-0")}},
			{Response: elc.MsgUpdateClientResponse{Message: []byte("msg-1"), Signature: []byte("sig-1")}},
			{Response: elc.MsgUpdateClientResponse{Message: []byte("msg-2"), Signature: []byte("sig-2")}},
		},
	})
}

type explicitStateBatchMultiRequestServer struct {
	elc.UnimplementedMsgServer
	captured *[]*ExecuteSpeculativeUpdateClientBatchRequest
}

func (s explicitStateBatchMultiRequestServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	*s.captured = append(*s.captured, req)
	units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, len(req.Units))
	for i := range req.Units {
		units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
			Response: elc.MsgUpdateClientResponse{
				Message:   []byte(fmt.Sprintf("msg-%s", req.Units[i].UnitId)),
				Signature: []byte(fmt.Sprintf("sig-%d", i)),
			},
		})
	}
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units:    units,
	})
}

type explicitStateIntegrationTestServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	captured **ExecuteSpeculativeUpdateClientBatchRequest
}

var (
	explicitStateTestHeaderedMessageABI, _ = abi.NewType("tuple", "struct HeaderedMessage", []abi.ArgumentMarshaling{
		{Name: "header", Type: "bytes32"},
		{Name: "message", Type: "bytes"},
	})
	explicitStateTestHeaderedContextABI, _ = abi.NewType("tuple", "struct HeaderedMessageContext", []abi.ArgumentMarshaling{
		{Name: "header", Type: "bytes32"},
		{Name: "context_bytes", Type: "bytes"},
	})
	explicitStateTestUpdateStateProxyMessageABI, _ = abi.NewType("tuple", "struct UpdateStateProxyMessage", []abi.ArgumentMarshaling{
		{Name: "prev_height", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "revision_number", Type: "uint64"},
			{Name: "revision_height", Type: "uint64"},
		}},
		{Name: "prev_state_id", Type: "bytes32"},
		{Name: "post_height", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "revision_number", Type: "uint64"},
			{Name: "revision_height", Type: "uint64"},
		}},
		{Name: "post_state_id", Type: "bytes32"},
		{Name: "timestamp", Type: "uint128"},
		{Name: "context", Type: "bytes"},
		{Name: "emitted_states", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "height", Type: "tuple", Components: []abi.ArgumentMarshaling{
				{Name: "revision_number", Type: "uint64"},
				{Name: "revision_height", Type: "uint64"},
			}},
			{Name: "state", Type: "bytes"},
		}},
	})
)

type explicitStateTestHeight struct {
	RevisionNumber uint64
	RevisionHeight uint64
}

type explicitStateTestEmittedState struct {
	Height explicitStateTestHeight
	State  []byte
}

type explicitStateTestUpdateStateProxyMessage struct {
	PrevHeight    explicitStateTestHeight
	PrevStateId   [32]byte
	PostHeight    explicitStateTestHeight
	PostStateId   [32]byte
	Timestamp     *big.Int
	Context       []byte
	EmittedStates []explicitStateTestEmittedState
}

func mustMakeExplicitStateTestEmptyContext() []byte {
	var header [32]byte
	binary.BigEndian.PutUint16(header[:2], lcptypes.LCPMessageContextTypeEmpty)
	bz, err := abi.Arguments{{Type: explicitStateTestHeaderedContextABI}}.Pack(struct {
		Header       [32]byte
		ContextBytes []byte
	}{
		Header:       header,
		ContextBytes: nil,
	})
	if err != nil {
		panic(err)
	}
	return bz
}

func mustMakeExplicitStateTestHeaderedUpdateStateMessage(postHeight uint64, stateIDByte byte) []byte {
	var postStateID [32]byte
	postStateID[31] = stateIDByte
	message, err := abi.Arguments{{Type: explicitStateTestUpdateStateProxyMessageABI}}.Pack(explicitStateTestUpdateStateProxyMessage{
		PostHeight: explicitStateTestHeight{
			RevisionNumber: 0,
			RevisionHeight: postHeight,
		},
		PostStateId:   postStateID,
		Timestamp:     big.NewInt(1),
		Context:       mustMakeExplicitStateTestEmptyContext(),
		EmittedStates: nil,
	})
	if err != nil {
		panic(err)
	}
	var header [32]byte
	binary.BigEndian.PutUint16(header[:2], lcptypes.LCPMessageVersion)
	binary.BigEndian.PutUint16(header[2:4], lcptypes.LCPMessageTypeUpdateState)
	bz, err := abi.Arguments{{Type: explicitStateTestHeaderedMessageABI}}.Pack(struct {
		Header  [32]byte
		Message []byte
	}{
		Header:  header,
		Message: message,
	})
	if err != nil {
		panic(err)
	}
	return bz
}

func (s explicitStateIntegrationTestServer) Client(_ context.Context, req *elc.QueryClientRequest) (*elc.QueryClientResponse, error) {
	clientStateAny, err := clienttypes.PackClientState(&lcptypes.ClientState{
		LatestHeight: clienttypes.Height{RevisionHeight: 7},
	})
	if err != nil {
		return nil, err
	}
	consensusStateAny, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{
		StateId: []byte("state-7"),
	})
	if err != nil {
		return nil, err
	}
	return &elc.QueryClientResponse{
		Found:          req.ClientId == "07-tendermint-11",
		ClientState:    clientStateAny,
		ConsensusState: consensusStateAny,
	}, nil
}

func (s explicitStateIntegrationTestServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	*s.captured = req
	units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, len(req.Units))
	for i := range req.Units {
		units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
			Response: elc.MsgUpdateClientResponse{
				Message:   mustMakeExplicitStateTestHeaderedUpdateStateMessage(uint64(11+i), byte(i+1)),
				Signature: []byte{byte('s'), byte('0' + i)},
			},
		})
	}
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units:    units,
	})
}

func recvSpeculativeBatchStreamRequest(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) (*ExecuteSpeculativeUpdateClientBatchRequest, error) {
	initChunk, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	init := initChunk.GetInit()
	if init == nil {
		return nil, fmt.Errorf("first stream chunk must be init")
	}
	req := &ExecuteSpeculativeUpdateClientBatchRequest{
		ClientId: init.ClientId,
	}
	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		unit := chunk.GetUnit()
		if unit == nil {
			return nil, fmt.Errorf("expected speculative batch unit chunk")
		}
		req.Units = append(req.Units, decodeGeneratedSpeculativeUnit(unit))
	}
	return req, nil
}

func decodeGeneratedSpeculativeUnit(unit *elc.SpeculativeUpdateClientUnit) *SpeculativeUpdateClientUnit {
	if unit == nil {
		return nil
	}
	return &SpeculativeUpdateClientUnit{
		UnitId:        unit.UnitId,
		Update:        &unit.Update,
		BaseState:     decodeGeneratedExplicitStateRef(&unit.BaseState),
		DependencyIds: append([]string(nil), unit.DependencyIds...),
	}
}

func decodeGeneratedExplicitStateRef(ref *elc.ExplicitStateRef) *ExplicitStateRef {
	if ref == nil {
		return nil
	}
	return &ExplicitStateRef{
		PrevHeight:     ref.PrevHeight,
		PrevStateId:    append([]byte(nil), ref.PrevStateId...),
		ClientState:    ref.ClientState,
		ConsensusState: ref.ConsensusState,
	}
}

type fakeOriginProver struct {
	headers             []core.Header
	explicitStateChunks []*ExplicitStateSourceHeaderUnit
}

func (p fakeOriginProver) Init(string, time.Duration, codec.ProtoCodecMarshaler, bool) error {
	return nil
}

func (p fakeOriginProver) SetRelayInfo(*core.PathEnd, *core.ProvableChain, *core.PathEnd) error {
	return nil
}

func (p fakeOriginProver) SetupForRelay(context.Context) error {
	return nil
}

func (p fakeOriginProver) CreateInitialLightClientState(context.Context, ibcexported.Height) (ibcexported.ClientState, ibcexported.ConsensusState, error) {
	return nil, nil, nil
}

func (p fakeOriginProver) SetupHeadersForUpdate(context.Context, core.FinalityAwareChain, core.Header) (<-chan *core.HeaderOrError, error) {
	return core.MakeHeaderStream(p.headers...), nil
}

func (p fakeOriginProver) SetupExplicitStateChunksForUpdate(context.Context, core.FinalityAwareChain, core.Header) ([]*ExplicitStateSourceHeaderUnit, error) {
	return p.explicitStateChunks, nil
}

func (p fakeOriginProver) CheckRefreshRequired(context.Context, core.ChainInfoICS02Querier) (bool, error) {
	return false, nil
}

func (p fakeOriginProver) GetLatestFinalizedHeader(context.Context) (core.Header, error) {
	if len(p.headers) == 0 {
		return nil, nil
	}
	return p.headers[len(p.headers)-1], nil
}

func (p fakeOriginProver) ProveState(core.QueryContext, string, []byte) ([]byte, clienttypes.Height, error) {
	return nil, clienttypes.Height{}, nil
}

func (p fakeOriginProver) ProveHostConsensusState(core.QueryContext, ibcexported.Height, ibcexported.ConsensusState) ([]byte, error) {
	return nil, nil
}

func TestNewLinearExplicitStateUpdatePlan(t *testing.T) {
	plan, err := newLinearExplicitStateUpdatePlan(
		"07-tendermint-0",
		[]*elc.MsgUpdateClient{
			{ClientId: "07-tendermint-0", Signer: []byte("a")},
			{ClientId: "07-tendermint-0", Signer: []byte("b")},
		},
		[]*ExplicitStateRef{
			{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
			{PrevHeight: &clienttypes.Height{RevisionHeight: 11}},
		},
	)
	if err != nil {
		t.Fatalf("newLinearExplicitStateUpdatePlan() error = %v", err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("unexpected plan units: %d", len(plan.Units))
	}
	if got := plan.Units[0].UnitID; got != "unit-0000" {
		t.Fatalf("unexpected first unit id: %s", got)
	}
	if len(plan.Units[0].DependencyIDs) != 0 {
		t.Fatalf("unexpected first unit dependencies: %v", plan.Units[0].DependencyIDs)
	}
	if got := plan.Units[1].UnitID; got != "unit-0001" {
		t.Fatalf("unexpected second unit id: %s", got)
	}
	if len(plan.Units[1].DependencyIDs) != 1 || plan.Units[1].DependencyIDs[0] != "unit-0000" {
		t.Fatalf("unexpected second unit dependencies: %v", plan.Units[1].DependencyIDs)
	}
	if len(plan.LaneWidths) != 1 || plan.LaneWidths[0] != 2 {
		t.Fatalf("unexpected lane widths: %v", plan.LaneWidths)
	}
}

func TestExplicitStateUpdatePlanBuildRequest(t *testing.T) {
	plan, err := newLinearExplicitStateUpdatePlan(
		"07-tendermint-1",
		[]*elc.MsgUpdateClient{
			{ClientId: "07-tendermint-1", Signer: []byte("signer")},
		},
		[]*ExplicitStateRef{
			{PrevHeight: &clienttypes.Height{RevisionHeight: 22}},
		},
	)
	if err != nil {
		t.Fatalf("newLinearExplicitStateUpdatePlan() error = %v", err)
	}
	req := plan.buildRequest()
	if req.ClientId != "07-tendermint-1" {
		t.Fatalf("unexpected request client id: %s", req.ClientId)
	}
	if len(req.Units) != 1 || req.Units[0] == nil {
		t.Fatalf("unexpected request units: %#v", req.Units)
	}
	if req.Units[0].UnitId != "unit-0000" {
		t.Fatalf("unexpected request unit id: %s", req.Units[0].UnitId)
	}
	if req.Units[0].BaseState == nil || req.Units[0].BaseState.PrevHeight == nil || req.Units[0].BaseState.PrevHeight.RevisionHeight != 22 {
		t.Fatalf("unexpected base state: %#v", req.Units[0].BaseState)
	}
}

func TestNewExplicitStateUpdatePlan(t *testing.T) {
	plan, err := newExplicitStateUpdatePlan(
		"07-tendermint-2",
		[]*ExplicitStatePlannedUnit{
			{
				UnitID:    "unit-a",
				Update:    &elc.MsgUpdateClient{ClientId: "07-tendermint-2"},
				BaseState: &ExplicitStateRef{},
			},
			{
				UnitID:        "unit-b",
				Update:        &elc.MsgUpdateClient{ClientId: "07-tendermint-2"},
				BaseState:     &ExplicitStateRef{},
				DependencyIDs: []string{"unit-a"},
			},
		},
	)
	if err != nil {
		t.Fatalf("newExplicitStateUpdatePlan() error = %v", err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("unexpected plan units: %d", len(plan.Units))
	}
}

func TestNewExplicitStateUpdatePlanRejectsDuplicateUnitID(t *testing.T) {
	_, err := newExplicitStateUpdatePlan(
		"07-tendermint-2",
		[]*ExplicitStatePlannedUnit{
			{
				UnitID:    "unit-a",
				Update:    &elc.MsgUpdateClient{ClientId: "07-tendermint-2"},
				BaseState: &ExplicitStateRef{},
			},
			{
				UnitID:    "unit-a",
				Update:    &elc.MsgUpdateClient{ClientId: "07-tendermint-2"},
				BaseState: &ExplicitStateRef{},
			},
		},
	)
	if err == nil {
		t.Fatal("expected duplicate unit_id error, got nil")
	}
}

func TestNewExplicitStateUpdatePlanRejectsUnknownDependency(t *testing.T) {
	_, err := newExplicitStateUpdatePlan(
		"07-tendermint-2",
		[]*ExplicitStatePlannedUnit{
			{
				UnitID:        "unit-a",
				Update:        &elc.MsgUpdateClient{ClientId: "07-tendermint-2"},
				BaseState:     &ExplicitStateRef{},
				DependencyIDs: []string{"unit-missing"},
			},
		},
	)
	if err == nil {
		t.Fatal("expected unknown dependency error, got nil")
	}
}

func TestNewLaneExplicitStateUpdatePlan(t *testing.T) {
	plan, err := newLaneExplicitStateUpdatePlan(
		"07-tendermint-9",
		[][]*elc.MsgUpdateClient{
			{
				{ClientId: "07-tendermint-9"},
				{ClientId: "07-tendermint-9"},
			},
			{
				{ClientId: "07-tendermint-9"},
			},
		},
		[][]*ExplicitStateRef{
			{
				{},
				{},
			},
			{
				{},
			},
		},
	)
	if err != nil {
		t.Fatalf("newLaneExplicitStateUpdatePlan() error = %v", err)
	}
	if len(plan.Units) != 3 {
		t.Fatalf("unexpected plan units: %d", len(plan.Units))
	}
	if len(plan.Units[0].DependencyIDs) != 0 {
		t.Fatalf("unexpected first lane root dependencies: %v", plan.Units[0].DependencyIDs)
	}
	if len(plan.Units[1].DependencyIDs) != 1 || plan.Units[1].DependencyIDs[0] != "unit-0000" {
		t.Fatalf("unexpected first lane second dependencies: %v", plan.Units[1].DependencyIDs)
	}
	if len(plan.Units[2].DependencyIDs) != 0 {
		t.Fatalf("unexpected second lane root dependencies: %v", plan.Units[2].DependencyIDs)
	}
	if len(plan.LaneWidths) != 2 || plan.LaneWidths[0] != 2 || plan.LaneWidths[1] != 1 {
		t.Fatalf("unexpected lane widths: %v", plan.LaneWidths)
	}
}

func TestNewLaneExplicitStateUpdatePlanBuildRequestPreservesLaneRoots(t *testing.T) {
	plan, err := newLaneExplicitStateUpdatePlan(
		"07-tendermint-10",
		[][]*elc.MsgUpdateClient{
			{
				{ClientId: "07-tendermint-10", Signer: []byte("lane-0")},
				{ClientId: "07-tendermint-10", Signer: []byte("lane-0")},
			},
			{
				{ClientId: "07-tendermint-10", Signer: []byte("lane-1")},
			},
		},
		[][]*ExplicitStateRef{
			{
				{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
				{PrevHeight: &clienttypes.Height{RevisionHeight: 11}},
			},
			{
				{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
			},
		},
	)
	if err != nil {
		t.Fatalf("newLaneExplicitStateUpdatePlan() error = %v", err)
	}

	req := plan.buildRequest()
	if len(req.Units) != 3 {
		t.Fatalf("unexpected request units: %d", len(req.Units))
	}
	if len(req.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected first lane root deps: %v", req.Units[0].DependencyIds)
	}
	if len(req.Units[1].DependencyIds) != 1 || req.Units[1].DependencyIds[0] != "unit-0000" {
		t.Fatalf("unexpected first lane chained deps: %v", req.Units[1].DependencyIds)
	}
	if len(req.Units[2].DependencyIds) != 0 {
		t.Fatalf("unexpected second lane root deps: %v", req.Units[2].DependencyIds)
	}
	if len(plan.LaneWidths) != 2 || plan.LaneWidths[0] != 2 || plan.LaneWidths[1] != 1 {
		t.Fatalf("unexpected lane widths: %v", plan.LaneWidths)
	}
}

func TestExecuteExplicitStateUpdatePlanInvokesMultiLaneBatch(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	plan, err := newLaneExplicitStateUpdatePlan(
		"07-tendermint-11",
		[][]*elc.MsgUpdateClient{
			{
				{ClientId: "07-tendermint-11", Signer: []byte("lane-0")},
				{ClientId: "07-tendermint-11", Signer: []byte("lane-0")},
			},
			{
				{ClientId: "07-tendermint-11", Signer: []byte("lane-1")},
			},
		},
		[][]*ExplicitStateRef{
			{
				{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
				{PrevHeight: &clienttypes.Height{RevisionHeight: 11}},
			},
			{
				{PrevHeight: &clienttypes.Height{RevisionHeight: 10}},
			},
		},
	)
	if err != nil {
		t.Fatalf("newLaneExplicitStateUpdatePlan() error = %v", err)
	}

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	t.Cleanup(server.Stop)

	var captured *ExecuteSpeculativeUpdateClientBatchRequest
	elc.RegisterMsgServer(server, &explicitStateBatchTestServer{captured: &captured})
	go func() {
		_ = server.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	pr := &Prover{lcpServiceClient: NewLCPServiceClient(conn)}
	results, err := pr.executeExplicitStateUpdatePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("executeExplicitStateUpdatePlan() error = %v", err)
	}

	if captured == nil {
		t.Fatal("expected speculative batch request to be captured")
	}
	if captured.ClientId != "07-tendermint-11" {
		t.Fatalf("unexpected request client id: %s", captured.ClientId)
	}
	if len(captured.Units) != 3 {
		t.Fatalf("unexpected request unit count: %d", len(captured.Units))
	}
	if len(captured.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected first lane root deps: %v", captured.Units[0].DependencyIds)
	}
	if len(captured.Units[1].DependencyIds) != 1 || captured.Units[1].DependencyIds[0] != "unit-0000" {
		t.Fatalf("unexpected first lane chained deps: %v", captured.Units[1].DependencyIds)
	}
	if len(captured.Units[2].DependencyIds) != 0 {
		t.Fatalf("unexpected second lane root deps: %v", captured.Units[2].DependencyIds)
	}
	if len(results) != 3 {
		t.Fatalf("unexpected results count: %d", len(results))
	}
	if string(results[0].Message) != "msg-0" || string(results[1].Message) != "msg-1" || string(results[2].Message) != "msg-2" {
		t.Fatalf("unexpected result messages: %#v", results)
	}
	if string(results[0].Signer) != "lane-0" || string(results[2].Signer) != "lane-1" {
		t.Fatalf("unexpected propagated signers: %#v", results)
	}
}

func TestUpdateELCForUpdateClientKeepsTendermintSharedTrustedHeightLinear(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	t.Setenv(envExplicitStateUpdateClient, "true")
	t.Setenv(envExplicitStateLaneStrategy, "shared_trusted_height")

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	var captured *ExecuteSpeculativeUpdateClientBatchRequest
	elc.RegisterQueryServer(server, &explicitStateIntegrationTestServer{captured: &captured})
	elc.RegisterMsgServer(server, &explicitStateIntegrationTestServer{captured: &captured})
	defer server.Stop()
	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.DialContext() error = %v", err)
	}
	defer conn.Close()

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	lcptypes.RegisterInterfaces(interfaceRegistry)
	coreCodec := codec.NewProtoCodec(interfaceRegistry)

	headers := []core.Header{
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
	}
	pr := &Prover{
		config: ProverConfig{ElcClientId: "07-tendermint-11"},
		codec:  coreCodec,
		originProver: fakeOriginProver{
			headers: headers,
		},
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: &enclave.EnclaveKeyInfo{
			KeyInfo: &enclave.EnclaveKeyInfo_Ias{
				Ias: &enclave.IASEnclaveKeyInfo{
					EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
				},
			},
		},
	}

	results, err := pr.updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		headers[len(headers)-1],
	)
	if err != nil {
		t.Fatalf("updateELCForUpdateClient() error = %v", err)
	}
	if captured == nil {
		t.Fatal("expected speculative batch request to be captured")
	}
	if len(captured.Units) != 2 {
		t.Fatalf("unexpected captured unit count: %d", len(captured.Units))
	}
	if captured.ClientId != "07-tendermint-11" {
		t.Fatalf("unexpected client id: %s", captured.ClientId)
	}
	if len(captured.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected first unit dependencies: %v", captured.Units[0].DependencyIds)
	}
	if len(captured.Units[1].DependencyIds) != 1 || captured.Units[1].DependencyIds[0] != "unit-0000" {
		t.Fatalf("unexpected second unit dependencies: %v", captured.Units[1].DependencyIds)
	}
	if captured.Units[0].BaseState == nil || captured.Units[0].BaseState.PrevHeight == nil || captured.Units[0].BaseState.PrevHeight.RevisionHeight != 10 {
		t.Fatalf("unexpected first base state: %#v", captured.Units[0].BaseState)
	}
	if captured.Units[1].BaseState == nil || captured.Units[1].BaseState.PrevHeight == nil || captured.Units[1].BaseState.PrevHeight.RevisionHeight != 10 {
		t.Fatalf("unexpected second base state: %#v", captured.Units[1].BaseState)
	}
	if len(results) != 2 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	wantSigner := common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
	for i, result := range results {
		if result == nil {
			t.Fatalf("result[%d] is nil", i)
		}
		msg, err := lcptypes.EthABIDecodeHeaderedProxyMessage(result.Message)
		if err != nil {
			t.Fatalf("result[%d] message decode error = %v", i, err)
		}
		updateStateMsg, err := msg.GetUpdateStateProxyMessage()
		if err != nil {
			t.Fatalf("result[%d] update-state decode error = %v", i, err)
		}
		if got, want := updateStateMsg.PostHeight.RevisionHeight, uint64(11+i); got != want {
			t.Fatalf("unexpected result[%d] post height: got=%d want=%d", i, got, want)
		}
		if string(result.Signer) != string(wantSigner) {
			t.Fatalf("unexpected result[%d] signer: %x", i, result.Signer)
		}
	}
}

func TestExplicitStateUpdatePlanSplitIntoExecutableBatches(t *testing.T) {
	plan, err := newLaneExplicitStateUpdatePlan(
		"07-tendermint-11",
		[][]*elc.MsgUpdateClient{{
			{ClientId: "07-tendermint-11", Signer: []byte("s0")},
			{ClientId: "07-tendermint-11", Signer: []byte("s1")},
			{ClientId: "07-tendermint-11", Signer: []byte("s2")},
		}},
		[][]*ExplicitStateRef{{
			{
				PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
				ClientState:    &codectypes.Any{TypeUrl: "client/0", Value: []byte("c0")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus/0", Value: []byte("s0")},
			},
			{
				PrevHeight:     &clienttypes.Height{RevisionHeight: 11},
				ClientState:    &codectypes.Any{TypeUrl: "client/1", Value: []byte("c1")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus/1", Value: []byte("s1")},
			},
			{
				PrevHeight:     &clienttypes.Height{RevisionHeight: 12},
				ClientState:    &codectypes.Any{TypeUrl: "client/2", Value: []byte("c2")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus/2", Value: []byte("s2")},
			},
		}},
	)
	if err != nil {
		t.Fatalf("newLaneExplicitStateUpdatePlan() error = %v", err)
	}

	batches, err := plan.splitIntoExecutableBatches(2)
	if err != nil {
		t.Fatalf("splitIntoExecutableBatches() error = %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("unexpected batch count: %d", len(batches))
	}
	if got := len(batches[0].Units); got != 2 {
		t.Fatalf("unexpected first batch size: %d", got)
	}
	if got := len(batches[1].Units); got != 1 {
		t.Fatalf("unexpected second batch size: %d", got)
	}
	if len(batches[0].Units[1].DependencyIDs) != 1 || batches[0].Units[1].DependencyIDs[0] != "unit-0000" {
		t.Fatalf("unexpected first batch dependencies: %v", batches[0].Units[1].DependencyIDs)
	}
	if len(batches[1].Units[0].DependencyIDs) != 0 {
		t.Fatalf("unexpected second batch root dependencies: %v", batches[1].Units[0].DependencyIDs)
	}
	if batches[1].Units[0].BaseState == nil || batches[1].Units[0].BaseState.ClientState == nil || batches[1].Units[0].BaseState.ConsensusState == nil {
		t.Fatalf("expected second batch root to retain explicit base state payload: %#v", batches[1].Units[0].BaseState)
	}
}

func TestExecuteExplicitStateUpdatePlanSplitsLargeRequests(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	t.Cleanup(server.Stop)

	var captured []*ExecuteSpeculativeUpdateClientBatchRequest
	elc.RegisterMsgServer(server, &explicitStateBatchMultiRequestServer{captured: &captured})
	go func() {
		_ = server.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	updates := make([]*elc.MsgUpdateClient, 0, maxSpeculativeBatchUnitsPerRequest+1)
	baseStates := make([]*ExplicitStateRef, 0, maxSpeculativeBatchUnitsPerRequest+1)
	for i := 0; i < maxSpeculativeBatchUnitsPerRequest+1; i++ {
		updates = append(updates, &elc.MsgUpdateClient{
			ClientId: "07-tendermint-11",
			Signer:   []byte(fmt.Sprintf("s%02d", i)),
		})
		baseStates = append(baseStates, &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: uint64(10 + i)},
			ClientState:    &codectypes.Any{TypeUrl: fmt.Sprintf("client/%d", i), Value: []byte(fmt.Sprintf("c%d", i))},
			ConsensusState: &codectypes.Any{TypeUrl: fmt.Sprintf("consensus/%d", i), Value: []byte(fmt.Sprintf("s%d", i))},
		})
	}
	plan, err := newLaneExplicitStateUpdatePlan(
		"07-tendermint-11",
		[][]*elc.MsgUpdateClient{updates},
		[][]*ExplicitStateRef{baseStates},
	)
	if err != nil {
		t.Fatalf("newLaneExplicitStateUpdatePlan() error = %v", err)
	}

	pr := &Prover{lcpServiceClient: NewLCPServiceClient(conn)}
	results, err := pr.executeExplicitStateUpdatePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("executeExplicitStateUpdatePlan() error = %v", err)
	}

	if len(captured) != 2 {
		t.Fatalf("unexpected request count: %d", len(captured))
	}
	if got := len(captured[0].Units); got != maxSpeculativeBatchUnitsPerRequest {
		t.Fatalf("unexpected first request size: %d", got)
	}
	if got := len(captured[1].Units); got != 1 {
		t.Fatalf("unexpected second request size: %d", got)
	}
	if len(captured[1].Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected split root dependencies: %v", captured[1].Units[0].DependencyIds)
	}
	if len(results) != maxSpeculativeBatchUnitsPerRequest+1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if string(results[0].Message) != "msg-unit-0000" {
		t.Fatalf("unexpected first result message: %s", string(results[0].Message))
	}
	lastIndex := maxSpeculativeBatchUnitsPerRequest
	wantLast := fmt.Sprintf("msg-unit-%04d", lastIndex)
	if string(results[lastIndex].Message) != wantLast {
		t.Fatalf("unexpected last result message: %s", string(results[lastIndex].Message))
	}
}

func TestUpdateELCForUpdateClientSingleHeaderStaysSingleLane(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	t.Setenv(envExplicitStateUpdateClient, "true")
	t.Setenv(envExplicitStateLaneStrategy, "shared_trusted_height")

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	var captured *ExecuteSpeculativeUpdateClientBatchRequest
	elc.RegisterQueryServer(server, &explicitStateIntegrationTestServer{captured: &captured})
	elc.RegisterMsgServer(server, &explicitStateIntegrationTestServer{captured: &captured})
	defer server.Stop()
	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.DialContext() error = %v", err)
	}
	defer conn.Close()

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	lcptypes.RegisterInterfaces(interfaceRegistry)
	coreCodec := codec.NewProtoCodec(interfaceRegistry)

	headers := []core.Header{
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
	}
	pr := &Prover{
		config: ProverConfig{ElcClientId: "07-tendermint-11"},
		codec:  coreCodec,
		originProver: fakeOriginProver{
			headers: headers,
		},
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: &enclave.EnclaveKeyInfo{
			KeyInfo: &enclave.EnclaveKeyInfo_Ias{
				Ias: &enclave.IASEnclaveKeyInfo{
					EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
				},
			},
		},
	}

	results, err := pr.updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		headers[0],
	)
	if err != nil {
		t.Fatalf("updateELCForUpdateClient() error = %v", err)
	}
	if captured == nil {
		t.Fatal("expected speculative batch request to be captured")
	}
	if len(captured.Units) != 1 {
		t.Fatalf("unexpected captured unit count: %d", len(captured.Units))
	}
	if len(captured.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected single-lane dependency ids: %v", captured.Units[0].DependencyIds)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestUpdateELCForUpdateClientFallsBackToSerialWhenBatchRPCUnavailable(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	t.Setenv(envExplicitStateUpdateClient, "true")

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	fallbackServer := &explicitStateFallbackTestServer{}
	elc.RegisterQueryServer(server, fallbackServer)
	elc.RegisterMsgServer(server, fallbackServer)
	defer server.Stop()
	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.DialContext() error = %v", err)
	}
	defer conn.Close()

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	lcptypes.RegisterInterfaces(interfaceRegistry)
	coreCodec := codec.NewProtoCodec(interfaceRegistry)

	anyHeader := mustPackTMHeaderForExplicitStateTest(t, 10)
	pr := &Prover{
		config: ProverConfig{ElcClientId: "07-tendermint-11"},
		codec:  coreCodec,
		originProver: fakeOriginProver{
			explicitStateChunks: []*ExplicitStateSourceHeaderUnit{
				{
					AnyHeader:     anyHeader,
					TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
					BaseState: &ExplicitStateRef{
						PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
						ClientState:    &codectypes.Any{TypeUrl: "client/0", Value: []byte("client")},
						ConsensusState: &codectypes.Any{TypeUrl: "consensus/0", Value: []byte("consensus")},
					},
				},
			},
		},
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: &enclave.EnclaveKeyInfo{
			KeyInfo: &enclave.EnclaveKeyInfo_Ias{
				Ias: &enclave.IASEnclaveKeyInfo{
					EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
				},
			},
		},
	}

	results, err := pr.updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
	)
	if err != nil {
		t.Fatalf("updateELCForUpdateClient() error = %v", err)
	}
	if fallbackServer.updateCalls != 1 {
		t.Fatalf("expected serial update-client fallback to be used once, got %d", fallbackServer.updateCalls)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if _, err := lcptypes.EthABIDecodeHeaderedProxyMessage(results[0].Message); err != nil {
		t.Fatalf("result message decode error = %v", err)
	}
}

func TestCollectExplicitStateSourceHeaderUnitsForUpdate(t *testing.T) {
	headers := []core.Header{
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
	}
	pr := &Prover{
		originProver: fakeOriginProver{headers: headers},
	}

	units, err := pr.collectExplicitStateSourceHeaderUnitsForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		headers[len(headers)-1],
	)
	if err != nil {
		t.Fatalf("collectExplicitStateSourceHeaderUnitsForUpdate() error = %v", err)
	}
	if len(units) != 2 {
		t.Fatalf("unexpected source unit count: %d", len(units))
	}
	for i, unit := range units {
		if unit == nil || unit.AnyHeader == nil {
			t.Fatalf("source unit[%d] missing packed header: %#v", i, unit)
		}
		if unit.TrustedHeight == nil || unit.TrustedHeight.RevisionHeight != 10 {
			t.Fatalf("unexpected source unit[%d] trusted height: %#v", i, unit.TrustedHeight)
		}
	}
}

func TestCollectExplicitStateSourceHeaderUnitsForUpdateUsesOverride(t *testing.T) {
	expected := []*ExplicitStateSourceHeaderUnit{
		{
			AnyHeader:     mustPackTMHeaderForExplicitStateTest(t, 12),
			TrustedHeight: &clienttypes.Height{RevisionHeight: 12},
		},
	}
	pr := &Prover{
		sourceHeaderCollector: func(_ context.Context, _ core.FinalityAwareChain, latest core.Header) ([]*ExplicitStateSourceHeaderUnit, error) {
			if latest == nil {
				t.Fatal("latest header must not be nil")
			}
			return expected, nil
		},
	}

	units, err := pr.collectExplicitStateSourceHeaderUnitsForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 12}},
	)
	if err != nil {
		t.Fatalf("collectExplicitStateSourceHeaderUnitsForUpdate() error = %v", err)
	}
	if len(units) != len(expected) || units[0] != expected[0] {
		t.Fatalf("unexpected override result: %#v", units)
	}
}

func TestCollectExplicitStateSourceHeaderUnitsForUpdateUsesChunkProvider(t *testing.T) {
	expectedBaseState := &ExplicitStateRef{
		PrevHeight:  &clienttypes.Height{RevisionHeight: 12},
		PrevStateId: []byte("state-12"),
	}
	expected := []*ExplicitStateSourceHeaderUnit{
		{
			AnyHeader:     mustPackTMHeaderForExplicitStateTest(t, 12),
			TrustedHeight: &clienttypes.Height{RevisionHeight: 12},
			BaseState:     expectedBaseState,
		},
	}
	pr := &Prover{
		originProver: fakeOriginProver{
			explicitStateChunks: expected,
		},
	}

	units, err := pr.collectExplicitStateSourceHeaderUnitsForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 12}},
	)
	if err != nil {
		t.Fatalf("collectExplicitStateSourceHeaderUnitsForUpdate() error = %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("unexpected source unit count: %d", len(units))
	}
	if units[0] != expected[0] {
		t.Fatalf("expected chunk provider result to be used directly: %#v", units[0])
	}
}

func TestBuildExplicitStateUpdatePlanForHeaderLanesUsesEmbeddedBaseState(t *testing.T) {
	anyHeader := mustPackTMHeaderForExplicitStateTest(t, 10)
	embedded := &ExplicitStateRef{
		PrevHeight:  &clienttypes.Height{RevisionHeight: 44},
		PrevStateId: []byte("embedded"),
	}
	pr := &Prover{}
	resolverCalls := 0

	plan, err := pr.buildExplicitStateUpdatePlanForHeaderLanesWithResolver(
		context.Background(),
		[][]*ExplicitStateHeaderUnit{
			{
				{
					Header:        anyHeader,
					TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
					BaseState:     embedded,
				},
			},
		},
		"07-tendermint-0",
		false,
		[]byte("signer"),
		func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error) {
			resolverCalls++
			return &ExplicitStateRef{PrevHeight: &clienttypes.Height{RevisionHeight: 99}}, nil
		},
	)
	if err != nil {
		t.Fatalf("buildExplicitStateUpdatePlanForHeaderLanesWithResolver() error = %v", err)
	}
	if resolverCalls != 0 {
		t.Fatalf("expected embedded base state to bypass resolver, got %d calls", resolverCalls)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("unexpected plan units: %d", len(plan.Units))
	}
	if plan.Units[0].BaseState == nil || plan.Units[0].BaseState.PrevHeight == nil || plan.Units[0].BaseState.PrevHeight.RevisionHeight != 44 {
		t.Fatalf("unexpected embedded base state: %#v", plan.Units[0].BaseState)
	}
	if string(plan.Units[0].BaseState.PrevStateId) != "embedded" {
		t.Fatalf("unexpected embedded prev_state_id: %x", plan.Units[0].BaseState.PrevStateId)
	}
	if plan.Units[0].BaseState == embedded {
		t.Fatal("expected embedded base state to be cloned")
	}
}
