package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type explicitStateBatchTestService interface {
	SpeculativeUpdateClientBatchStream(elc.Msg_SpeculativeUpdateClientBatchStreamServer) error
}

type explicitStateFallbackTestServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	batchCalls  int
	updateCalls int
}

func (s *explicitStateFallbackTestServer) SpeculativeUpdateClientBatchStream(elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	s.batchCalls++
	return status.Error(codes.Unimplemented, "method SpeculativeUpdateClientBatchStream not implemented")
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

type explicitStateSourceUnitStreamingObserveServer struct {
	elc.UnimplementedMsgServer
	firstUnitEnd chan struct{}
}

func (s explicitStateSourceUnitStreamingObserveServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	unitCount := 0
	for {
		chunk, err := stream.Recv()
		if err != nil {
			return err
		}
		switch c := chunk.GetChunk().(type) {
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitEnd:
			unitCount++
			if c.UnitEnd.UnitId == "unit-0000" {
				close(s.firstUnitEnd)
			}
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_BatchEnd:
			units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, unitCount)
			for i := 0; i < unitCount; i++ {
				units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
					Response: elc.MsgUpdateClientResponse{
						Message:   []byte(fmt.Sprintf("msg-%d", i)),
						Signature: []byte(fmt.Sprintf("sig-%d", i)),
					},
				})
			}
			return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
				ClientId: "07-tendermint-11",
				Units:    units,
			})
		}
	}
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
	var openUnit *SpeculativeUpdateClientUnit
	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				if openUnit != nil {
					return nil, fmt.Errorf("unexpected EOF while unit %q is open", openUnit.UnitId)
				}
				break
			}
			return nil, err
		}
		switch c := chunk.GetChunk().(type) {
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitInit:
			if openUnit != nil {
				return nil, fmt.Errorf("received unit init while unit %q is open", openUnit.UnitId)
			}
			if c.UnitInit == nil {
				return nil, fmt.Errorf("received nil unit init")
			}
			openUnit = &SpeculativeUpdateClientUnit{
				UnitId: c.UnitInit.UnitId,
				Update: &elc.MsgUpdateClient{
					ClientId:     init.ClientId,
					Header:       &codectypes.Any{TypeUrl: c.UnitInit.TypeUrl},
					IncludeState: c.UnitInit.IncludeState,
					Signer:       append([]byte(nil), c.UnitInit.Signer...),
				},
				BaseState: decodeGeneratedExplicitStateRef(&c.UnitInit.BaseState),
			}
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitHeaderChunk:
			if openUnit == nil {
				return nil, fmt.Errorf("received unit header chunk without open unit")
			}
			if c.UnitHeaderChunk == nil {
				return nil, fmt.Errorf("received nil unit header chunk")
			}
			if c.UnitHeaderChunk.UnitId != openUnit.UnitId {
				return nil, fmt.Errorf("unit header chunk id mismatch: open=%q chunk=%q", openUnit.UnitId, c.UnitHeaderChunk.UnitId)
			}
			openUnit.Update.Header.Value = append(openUnit.Update.Header.Value, c.UnitHeaderChunk.Data...)
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_UnitEnd:
			if openUnit == nil {
				return nil, fmt.Errorf("received unit end without open unit")
			}
			if c.UnitEnd == nil {
				return nil, fmt.Errorf("received nil unit end")
			}
			if c.UnitEnd.UnitId != openUnit.UnitId {
				return nil, fmt.Errorf("unit end id mismatch: open=%q end=%q", openUnit.UnitId, c.UnitEnd.UnitId)
			}
			req.Units = append(req.Units, openUnit)
			openUnit = nil
		case *elc.MsgSpeculativeUpdateClientBatchStreamChunk_BatchEnd:
			if openUnit != nil {
				return nil, fmt.Errorf("received batch end while unit %q is open", openUnit.UnitId)
			}
			return req, nil
		default:
			return nil, fmt.Errorf("expected speculative batch unit chunk")
		}
	}
	return req, nil
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

func (p fakeOriginProver) SetupExplicitStateChunksForUpdate(context.Context, core.FinalityAwareChain, core.Header) (<-chan *ExplicitStateSourceHeaderUnitOrError, error) {
	return makeExplicitStateSourceHeaderUnitStream(p.explicitStateChunks), nil
}

func mustExplicitStateSourceUnitsFromHeaders(t *testing.T, headers ...core.Header) []*ExplicitStateSourceHeaderUnit {
	t.Helper()
	units, err := collectExplicitStateSourceHeaderUnits(core.MakeHeaderStream(headers...))
	if err != nil {
		t.Fatalf("collectExplicitStateSourceHeaderUnits() error = %v", err)
	}
	return units
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

func makeSpeculativeBatchTestUpdate(clientID string, signer []byte, index int) *elc.MsgUpdateClient {
	return &elc.MsgUpdateClient{
		ClientId: clientID,
		Header: &codectypes.Any{
			TypeUrl: "/test.Header",
			Value:   []byte(fmt.Sprintf("header-%d", index)),
		},
		Signer: signer,
	}
}

func TestExecuteExplicitStateSourceHeaderUnitStreamSendsUnitBeforeReceivingAllUnits(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	t.Cleanup(server.Stop)

	firstUnitEnd := make(chan struct{})
	observeServer := &explicitStateSourceUnitStreamingObserveServer{firstUnitEnd: firstUnitEnd}
	elc.RegisterMsgServer(server, observeServer)
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

	unitStream := make(chan *ExplicitStateSourceHeaderUnitOrError)
	done := make(chan error, 1)
	pr := &Prover{
		config:           ProverConfig{ElcClientId: "07-tendermint-11"},
		lcpServiceClient: NewLCPServiceClient(conn),
	}
	go func() {
		results, err := pr.executeExplicitStateELCUpdateSourceHeaderUnitStream(
			context.Background(),
			unitStream,
			"07-tendermint-11",
			false,
			[]byte("signer"),
			"test",
		)
		if err != nil {
			done <- err
			return
		}
		if len(results) != 2 {
			done <- fmt.Errorf("unexpected result count: %d", len(results))
			return
		}
		done <- nil
	}()

	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader:     makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 0).Header,
		TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
		BaseState: &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
			ClientState:    &codectypes.Any{TypeUrl: "client/10", Value: []byte("client-10")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/10", Value: []byte("consensus-10")},
		},
	}}
	select {
	case <-firstUnitEnd:
	case <-time.After(2 * time.Second):
		t.Fatal("first unit was not streamed before the second source unit was provided")
	}
	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader:     makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 1).Header,
		TrustedHeight: &clienttypes.Height{RevisionHeight: 11},
		BaseState: &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 11},
			ClientState:    &codectypes.Any{TypeUrl: "client/11", Value: []byte("client-11")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/11", Value: []byte("consensus-11")},
		},
	}}
	close(unitStream)

	if err := <-done; err != nil {
		t.Fatalf("executeExplicitStateELCUpdateSourceHeaderUnitStream() error = %v", err)
	}
}

func TestUpdateELCForUpdateClientKeepsTendermintHeadersOrdered(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

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
			headers:             headers,
			explicitStateChunks: mustExplicitStateSourceUnitsFromHeaders(t, headers...),
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

func TestUpdateELCForEnclaveKeyUpdateUsesSpeculativeBatchStream(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

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
		&tmclienttypes.Header{
			TrustedHeight: clienttypes.Height{RevisionHeight: 10},
			SignedHeader:  &tmproto.SignedHeader{Header: &tmproto.Header{Height: 11}},
		},
		&tmclienttypes.Header{
			TrustedHeight: clienttypes.Height{RevisionHeight: 10},
			SignedHeader:  &tmproto.SignedHeader{Header: &tmproto.Header{Height: 12}},
		},
	}
	baseStates := []*ExplicitStateRef{
		{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
			ClientState:    &codectypes.Any{TypeUrl: "client/10", Value: []byte("client-10")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/10", Value: []byte("consensus-10")},
		},
		{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
			ClientState:    &codectypes.Any{TypeUrl: "client/10b", Value: []byte("client-10b")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/10b", Value: []byte("consensus-10b")},
		},
	}
	pr := &Prover{
		config: ProverConfig{ElcClientId: "07-tendermint-11"},
		codec:  coreCodec,
		originProver: fakeOriginProver{
			headers: headers,
			explicitStateChunks: []*ExplicitStateSourceHeaderUnit{
				{
					AnyHeader:     mustPackTMHeaderForExplicitStateTest(t, 10),
					TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
					BaseState:     baseStates[0],
				},
				{
					AnyHeader:     mustPackTMHeaderForExplicitStateTest(t, 10),
					TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
					BaseState:     baseStates[1],
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

	responses, err := pr.updateELC(context.Background(), "07-tendermint-11", true)
	if err != nil {
		t.Fatalf("updateELC() error = %v", err)
	}
	if captured == nil {
		t.Fatal("expected speculative batch request to be captured")
	}
	if captured.ClientId != "07-tendermint-11" {
		t.Fatalf("unexpected client id: %s", captured.ClientId)
	}
	if len(captured.Units) != 2 {
		t.Fatalf("unexpected captured unit count: %d", len(captured.Units))
	}
	for i, unit := range captured.Units {
		if unit.Update == nil {
			t.Fatalf("unit[%d] update is nil", i)
		}
		if !unit.Update.IncludeState {
			t.Fatalf("unit[%d] include_state is false", i)
		}
		if unit.BaseState == nil || unit.BaseState.ClientState == nil || unit.BaseState.ConsensusState == nil {
			t.Fatalf("unit[%d] missing embedded base state: %#v", i, unit.BaseState)
		}
	}
	if len(responses) != 2 {
		t.Fatalf("unexpected response count: %d", len(responses))
	}
}

func TestExecuteExplicitStateHeaderUnitsStreamSplitsLargeRequests(t *testing.T) {
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

	headerUnits := make([]*ExplicitStateHeaderUnit, 0, DefaultMaxSpeculativeBatchUnits+1)
	for i := 0; i < DefaultMaxSpeculativeBatchUnits+1; i++ {
		headerUnits = append(headerUnits, &ExplicitStateHeaderUnit{
			Header: makeSpeculativeBatchTestUpdate(
				"07-tendermint-11",
				[]byte(fmt.Sprintf("s%02d", i)),
				i,
			).Header,
			TrustedHeight: &clienttypes.Height{RevisionHeight: uint64(10 + i)},
			BaseState: &ExplicitStateRef{
				PrevHeight:     &clienttypes.Height{RevisionHeight: uint64(10 + i)},
				ClientState:    &codectypes.Any{TypeUrl: fmt.Sprintf("client/%d", i), Value: []byte(fmt.Sprintf("c%d", i))},
				ConsensusState: &codectypes.Any{TypeUrl: fmt.Sprintf("consensus/%d", i), Value: []byte(fmt.Sprintf("s%d", i))},
			},
		})
	}

	pr := &Prover{lcpServiceClient: NewLCPServiceClient(conn)}
	results, err := pr.executeExplicitStateHeaderUnitsStreamWithResolver(
		context.Background(),
		headerUnits,
		"07-tendermint-11",
		false,
		[]byte("signer"),
		func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error) {
			t.Fatal("resolver should not be called for embedded base states")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("executeExplicitStateHeaderUnitsStreamWithResolver() error = %v", err)
	}

	if len(captured) != 2 {
		t.Fatalf("unexpected request count: %d", len(captured))
	}
	if got := len(captured[0].Units); got != DefaultMaxSpeculativeBatchUnits {
		t.Fatalf("unexpected first request size: %d", got)
	}
	if got := len(captured[1].Units); got != 1 {
		t.Fatalf("unexpected second request size: %d", got)
	}
	if len(results) != DefaultMaxSpeculativeBatchUnits+1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if string(results[0].Message) != "msg-unit-0000" {
		t.Fatalf("unexpected first result message: %s", string(results[0].Message))
	}
	lastIndex := DefaultMaxSpeculativeBatchUnits
	wantLast := fmt.Sprintf("msg-unit-%04d", lastIndex)
	if string(results[lastIndex].Message) != wantLast {
		t.Fatalf("unexpected last result message: %s", string(results[lastIndex].Message))
	}
}

func TestExecuteExplicitStateHeaderUnitsStreamRejectsDeferredBatchBoundaryBeforeOpeningStream(t *testing.T) {
	headerUnits := make([]*ExplicitStateHeaderUnit, 0, DefaultMaxSpeculativeBatchUnits+1)
	for i := 0; i < DefaultMaxSpeculativeBatchUnits+1; i++ {
		headerUnits = append(headerUnits, &ExplicitStateHeaderUnit{
			Header: &codectypes.Any{TypeUrl: "header", Value: []byte{byte(i)}},
		})
	}

	resolveCalls := 0
	pr := &Prover{}
	_, err := pr.executeExplicitStateHeaderUnitsStreamWithResolver(
		context.Background(),
		headerUnits,
		"07-tendermint-11",
		false,
		[]byte("signer"),
		func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error) {
			resolveCalls++
			return &ExplicitStateRef{
				ClientState:    &codectypes.Any{TypeUrl: "client", Value: []byte("c")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus", Value: []byte("s")},
			}, nil
		},
	)
	if err == nil {
		t.Fatal("expected deferred batch boundary error")
	}
	if !strings.Contains(err.Error(), "batch boundary requires canonical base state payload") {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("expected validation before resolving base states, got %d resolver calls", resolveCalls)
	}
}

func TestUpdateELCForUpdateClientSingleHeaderStaysSingleUnitBatch(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
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
			headers:             headers,
			explicitStateChunks: mustExplicitStateSourceUnitsFromHeaders(t, headers...),
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
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestUpdateELCForUpdateClientFallsBackToSerialWhenBatchRPCUnavailable(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

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
	if fallbackServer.batchCalls != 1 {
		t.Fatalf("expected speculative batch to be attempted once, got %d", fallbackServer.batchCalls)
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

func TestUpdateELCForUpdateClientDisablesExplicitStateWhenEnvFalse(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	t.Setenv(envExplicitStateUpdateClient, "false")

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

	header := &tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}}
	pr := &Prover{
		config: ProverConfig{ElcClientId: "07-tendermint-11"},
		codec:  coreCodec,
		originProver: fakeOriginProver{
			headers:             []core.Header{header},
			explicitStateChunks: mustExplicitStateSourceUnitsFromHeaders(t, header),
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
		header,
	)
	if err != nil {
		t.Fatalf("updateELCForUpdateClient() error = %v", err)
	}
	if fallbackServer.batchCalls != 0 {
		t.Fatalf("expected speculative batch to be disabled, got %d calls", fallbackServer.batchCalls)
	}
	if fallbackServer.updateCalls != 1 {
		t.Fatalf("expected serial update-client to be used once, got %d", fallbackServer.updateCalls)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestShouldLogSerialUpdateClientFallbackSuppressesUnimplemented(t *testing.T) {
	err := fmt.Errorf(
		"failed explicit-state update client batch: %w",
		status.Error(codes.Unimplemented, "method SpeculativeUpdateClientBatchStream not implemented"),
	)

	if !shouldFallbackToSerialUpdateClient(err) {
		t.Fatal("expected Unimplemented to trigger serial fallback")
	}
	if shouldLogSerialUpdateClientFallback(err) {
		t.Fatal("expected Unimplemented fallback log to be suppressed")
	}
}

func TestShouldLogSerialUpdateClientFallbackKeepsEOF(t *testing.T) {
	err := fmt.Errorf("send failed: %w", io.EOF)

	if !shouldFallbackToSerialUpdateClient(err) {
		t.Fatal("expected EOF to trigger serial fallback")
	}
	if !shouldLogSerialUpdateClientFallback(err) {
		t.Fatal("expected EOF fallback log to be kept")
	}
}

func TestCollectExplicitStateChunkSourceHeaderUnitStreamForUpdateUsesOverride(t *testing.T) {
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

	unitStream, ok, err := pr.collectExplicitStateChunkSourceHeaderUnitStreamForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 12}},
	)
	if err != nil {
		t.Fatalf("collectExplicitStateChunkSourceHeaderUnitStreamForUpdate() error = %v", err)
	}
	if !ok {
		t.Fatal("expected override to be used")
	}
	units, err := drainExplicitStateSourceHeaderUnitStream(unitStream)
	if err != nil {
		t.Fatalf("drainExplicitStateSourceHeaderUnitStream() error = %v", err)
	}
	if len(units) != len(expected) || units[0] != expected[0] {
		t.Fatalf("unexpected override result: %#v", units)
	}
}

func TestCollectExplicitStateChunkSourceHeaderUnitStreamForUpdateUsesChunkProvider(t *testing.T) {
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

	unitStream, ok, err := pr.collectExplicitStateChunkSourceHeaderUnitStreamForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 12}},
	)
	if err != nil {
		t.Fatalf("collectExplicitStateChunkSourceHeaderUnitStreamForUpdate() error = %v", err)
	}
	if !ok {
		t.Fatal("expected chunk provider to be used")
	}
	units, err := drainExplicitStateSourceHeaderUnitStream(unitStream)
	if err != nil {
		t.Fatalf("drainExplicitStateSourceHeaderUnitStream() error = %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("unexpected source unit count: %d", len(units))
	}
	if units[0] != expected[0] {
		t.Fatalf("expected chunk provider result to be used directly: %#v", units[0])
	}
}

func TestExecuteExplicitStateHeaderUnitsStreamRejectsEmbeddedBaseStateHeightMismatch(t *testing.T) {
	anyHeader := mustPackTMHeaderForExplicitStateTest(t, 10)
	pr := &Prover{}

	_, err := pr.executeExplicitStateHeaderUnitsStreamWithResolver(
		context.Background(),
		[]*ExplicitStateHeaderUnit{
			{
				Header:        anyHeader,
				TrustedHeight: &clienttypes.Height{RevisionHeight: 10},
				BaseState: &ExplicitStateRef{
					PrevHeight:     &clienttypes.Height{RevisionHeight: 11},
					ClientState:    &codectypes.Any{TypeUrl: "client", Value: []byte("c")},
					ConsensusState: &codectypes.Any{TypeUrl: "consensus", Value: []byte("s")},
				},
			},
		},
		"07-tendermint-0",
		false,
		[]byte("signer"),
		func(context.Context, string, *codectypes.Any) (*ExplicitStateRef, error) {
			t.Fatal("resolver should not be called for embedded base state")
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected embedded base state height mismatch error")
	}
	if !strings.Contains(err.Error(), "base_state prev_height mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
