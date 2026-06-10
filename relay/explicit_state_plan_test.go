package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
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
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
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

type unsupportedSpeculativeBatchServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	batchCalls  int
	updateCalls int
}

func (s *unsupportedSpeculativeBatchServer) Client(context.Context, *elc.QueryClientRequest) (*elc.QueryClientResponse, error) {
	return makeExplicitStateQueryClientResponse(10)
}

func (s *unsupportedSpeculativeBatchServer) SpeculativeUpdateClientBatchStream(elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	s.batchCalls++
	return status.Error(codes.Unimplemented, "method SpeculativeUpdateClientBatchStream not implemented")
}

func (s *unsupportedSpeculativeBatchServer) UpdateClientStream(stream elc.Msg_UpdateClientStreamServer) error {
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

type blockingSpeculativeBatchErrorServer struct {
	elc.UnimplementedMsgServer
	secondSendAttempted <-chan struct{}
}

func (s blockingSpeculativeBatchErrorServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	if len(req.Units) != 1 {
		return fmt.Errorf("expected exactly one unit before batch failure, got %d", len(req.Units))
	}
	select {
	case <-s.secondSendAttempted:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("producer did not attempt the second send before batch failure")
	}
	return status.Error(codes.Aborted, "test speculative batch failure")
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
			if c.UnitEnd.UnitId == "batch-0/unit-0" {
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

type explicitStateSplitBoundaryServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	batchCalls      int
	batchUnitCounts []int
	updateCalls     int
}

func (s *explicitStateSplitBoundaryServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	s.batchCalls++
	s.batchUnitCounts = append(s.batchUnitCounts, len(req.Units))
	units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, len(req.Units))
	for i := range req.Units {
		units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
			Response: elc.MsgUpdateClientResponse{
				Message:   mustMakeExplicitStateTestHeaderedUpdateStateMessage(uint64(11+i), byte(i)),
				Signature: []byte(fmt.Sprintf("batch-sig-%d", i)),
			},
		})
	}
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units:    units,
	})
}

func (s *explicitStateSplitBoundaryServer) UpdateClientStream(stream elc.Msg_UpdateClientStreamServer) error {
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			s.updateCalls++
			return stream.SendAndClose(&elc.MsgUpdateClientResponse{
				Message:   mustMakeExplicitStateTestHeaderedUpdateStateMessage(uint64(20+s.updateCalls), byte(10+s.updateCalls)),
				Signature: []byte(fmt.Sprintf("serial-sig-%d", s.updateCalls)),
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
	// The canonical base height must match the first source unit's
	// prev_height (10) used by the integration fixtures; the relayer now
	// rejects providers whose first unit does not anchor at the queried base.
	clientStateAny, err := clienttypes.PackClientState(&lcptypes.ClientState{
		LatestHeight: clienttypes.Height{RevisionHeight: 10},
	})
	if err != nil {
		return nil, err
	}
	consensusStateAny, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{
		StateId: []byte("state-10"),
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

type explicitStateParityTestServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	batchCalls  int
	updateCalls int
}

func (s *explicitStateParityTestServer) Client(context.Context, *elc.QueryClientRequest) (*elc.QueryClientResponse, error) {
	return makeExplicitStateQueryClientResponse(10)
}

func (s *explicitStateParityTestServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	s.batchCalls++
	units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, len(req.Units))
	for i := range req.Units {
		units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
			Response: makeExplicitStateParityResponse(i),
		})
	}
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units:    units,
	})
}

func (s *explicitStateParityTestServer) UpdateClientStream(stream elc.Msg_UpdateClientStreamServer) error {
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			resp := makeExplicitStateParityResponse(s.updateCalls)
			s.updateCalls++
			return stream.SendAndClose(&resp)
		}
		if err != nil {
			return err
		}
		if chunk == nil {
			return fmt.Errorf("received nil update client stream chunk")
		}
	}
}

func makeExplicitStateParityResponse(i int) elc.MsgUpdateClientResponse {
	return elc.MsgUpdateClientResponse{
		Message:   mustMakeExplicitStateTestHeaderedUpdateStateMessage(uint64(11+i), byte(i+1)),
		Signature: []byte(fmt.Sprintf("sig-%d", i)),
	}
}

func makeExplicitStateQueryClientResponse(height uint64) (*elc.QueryClientResponse, error) {
	clientStateAny, err := clienttypes.PackClientState(&lcptypes.ClientState{
		LatestHeight: clienttypes.Height{RevisionHeight: height},
	})
	if err != nil {
		return nil, err
	}
	consensusStateAny, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{
		StateId: []byte(fmt.Sprintf("state-%d", height)),
	})
	if err != nil {
		return nil, err
	}
	return &elc.QueryClientResponse{
		Found:          true,
		ClientState:    clientStateAny,
		ConsensusState: consensusStateAny,
	}, nil
}

type explicitStateCanonicalRetryServer struct {
	elc.UnimplementedQueryServer
	elc.UnimplementedMsgServer
	queryCalls int
	batchCalls int
}

func (s *explicitStateCanonicalRetryServer) Client(_ context.Context, req *elc.QueryClientRequest) (*elc.QueryClientResponse, error) {
	s.queryCalls++
	if req.ClientId != "07-tendermint-11" {
		return &elc.QueryClientResponse{Found: false}, nil
	}
	height := clienttypes.Height{RevisionHeight: uint64(6 + s.queryCalls)}
	clientStateAny, err := clienttypes.PackClientState(&lcptypes.ClientState{
		LatestHeight: height,
	})
	if err != nil {
		return nil, err
	}
	consensusStateAny, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{
		StateId: []byte(fmt.Sprintf("state-%d", height.RevisionHeight)),
	})
	if err != nil {
		return nil, err
	}
	return &elc.QueryClientResponse{
		Found:          true,
		ClientState:    clientStateAny,
		ConsensusState: consensusStateAny,
	}, nil
}

func (s *explicitStateCanonicalRetryServer) SpeculativeUpdateClientBatchStream(stream elc.Msg_SpeculativeUpdateClientBatchStreamServer) error {
	req, err := recvSpeculativeBatchStreamRequest(stream)
	if err != nil {
		return err
	}
	s.batchCalls++
	if s.batchCalls == 1 {
		return status.Error(codes.Aborted, "BaseStateMismatch: invalid argument: descr=stored speculative base client_state mismatch: client_id=07-tendermint-11")
	}
	units := make([]*elc.StitchedSpeculativeUpdateClientUnitResult, 0, len(req.Units))
	for i := range req.Units {
		units = append(units, &elc.StitchedSpeculativeUpdateClientUnitResult{
			Response: makeExplicitStateParityResponse(i),
		})
	}
	return stream.SendAndClose(&elc.ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: req.ClientId,
		Units:    units,
	})
}

type fakeOriginProverWithBase struct {
	fakeOriginProver
	bases []*ExplicitStateBase
}

func (p *fakeOriginProverWithBase) SetupExplicitStateChunksForUpdate(
	_ context.Context,
	_ core.FinalityAwareChain,
	_ core.Header,
	base *ExplicitStateBase,
) (<-chan *ExplicitStateSourceHeaderUnitOrError, error) {
	p.bases = append(p.bases, base)
	if base == nil {
		height := clienttypes.Height{RevisionHeight: 1}
		clientStateAny, err := clienttypes.PackClientState(&lcptypes.ClientState{
			LatestHeight: height,
		})
		if err != nil {
			return nil, err
		}
		consensusStateAny, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{
			StateId: []byte("state-1"),
		})
		if err != nil {
			return nil, err
		}
		base = &ExplicitStateBase{
			Height:         height,
			ClientState:    clientStateAny,
			ConsensusState: consensusStateAny,
		}
	}
	anyHeader, err := codectypes.NewAnyWithValue(&tmclienttypes.Header{
		TrustedHeight: base.Height,
	})
	if err != nil {
		return nil, err
	}
	return makeExplicitStateSourceHeaderUnitStream([]*ExplicitStateSourceHeaderUnit{
		{
			AnyHeader: anyHeader,
			BaseState: &ExplicitStateRef{
				PrevHeight:     &base.Height,
				ClientState:    base.ClientState,
				ConsensusState: base.ConsensusState,
			},
		},
	}), nil
}

type fakeOriginProverWithInitialState struct {
	fakeOriginProver
	requestedHeights []ibcexported.Height
}

func (p *fakeOriginProverWithInitialState) CreateInitialLightClientState(_ context.Context, height ibcexported.Height) (ibcexported.ClientState, ibcexported.ConsensusState, error) {
	p.requestedHeights = append(p.requestedHeights, height)
	h, ok := height.(clienttypes.Height)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected height type: %T", height)
	}
	return &lcptypes.ClientState{LatestHeight: h}, &lcptypes.ConsensusState{StateId: []byte(fmt.Sprintf("elc-state-%d", h.RevisionHeight))}, nil
}

type fakeOnChainLCPChain struct {
	core.FinalityAwareChain
	queryHeight       ibcexported.Height
	clientStateHeight clienttypes.Height
	stateID           []byte
	consensusQueries  []ibcexported.Height
}

func (c *fakeOnChainLCPChain) LatestHeight(context.Context) (ibcexported.Height, error) {
	return c.queryHeight, nil
}

func (c *fakeOnChainLCPChain) QueryClientState(core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
	any, err := clienttypes.PackClientState(&lcptypes.ClientState{LatestHeight: c.clientStateHeight})
	if err != nil {
		return nil, err
	}
	return &clienttypes.QueryClientStateResponse{ClientState: any}, nil
}

func (c *fakeOnChainLCPChain) QueryClientConsensusState(_ core.QueryContext, height ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {
	c.consensusQueries = append(c.consensusQueries, height)
	any, err := clienttypes.PackConsensusState(&lcptypes.ConsensusState{StateId: append([]byte(nil), c.stateID...)})
	if err != nil {
		return nil, err
	}
	return &clienttypes.QueryConsensusStateResponse{ConsensusState: any}, nil
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

func (p fakeOriginProver) SetupExplicitStateChunksForUpdate(context.Context, core.FinalityAwareChain, core.Header, *ExplicitStateBase) (<-chan *ExplicitStateSourceHeaderUnitOrError, error) {
	return makeExplicitStateSourceHeaderUnitStream(p.explicitStateChunks), nil
}

func mustExplicitStateSourceUnitsFromHeaders(t *testing.T, headers ...core.Header) []*ExplicitStateSourceHeaderUnit {
	t.Helper()
	units, err := collectExplicitStateSourceHeaderUnitsForTest(core.MakeHeaderStream(headers...))
	if err != nil {
		t.Fatalf("collectExplicitStateSourceHeaderUnitsForTest() error = %v", err)
	}
	return units
}

func collectExplicitStateSourceHeaderUnitsForTest(
	headerStream <-chan *core.HeaderOrError,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	var units []*ExplicitStateSourceHeaderUnit
	i := 0
	for h := range headerStream {
		unit, err := explicitStateSourceHeaderUnitFromStreamItemForTest(h, i)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
		i += 1
	}
	return units, nil
}

func explicitStateSourceHeaderUnitFromStreamItemForTest(
	h *core.HeaderOrError,
	i int,
) (*ExplicitStateSourceHeaderUnit, error) {
	if h == nil {
		return nil, fmt.Errorf("received nil header stream item: i=%v", i)
	}
	if h.Error != nil {
		return nil, fmt.Errorf("failed to setup a header for update: i=%v %w", i, h.Error)
	}
	if h.Header == nil {
		return nil, fmt.Errorf("received nil header in header stream: i=%v", i)
	}
	anyHeader, err := clienttypes.PackClientMessage(h.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to pack header: i=%v header=%v %w", i, h.Header, err)
	}
	return &ExplicitStateSourceHeaderUnit{
		Header:    h.Header,
		AnyHeader: anyHeader,
	}, nil
}

func mustExplicitStateSourceUnitsWithBaseStatesFromHeaders(t *testing.T, headers ...core.Header) []*ExplicitStateSourceHeaderUnit {
	t.Helper()
	units := mustExplicitStateSourceUnitsFromHeaders(t, headers...)
	for i, unit := range units {
		if unit == nil {
			t.Fatalf("source unit[%d] is nil", i)
		}
		prevHeight := &clienttypes.Height{RevisionHeight: uint64(i + 10)}
		unit.BaseState = &ExplicitStateRef{
			PrevHeight:     prevHeight,
			ClientState:    &codectypes.Any{TypeUrl: fmt.Sprintf("client/%d", i), Value: []byte(fmt.Sprintf("client-%d", i))},
			ConsensusState: &codectypes.Any{TypeUrl: fmt.Sprintf("consensus/%d", i), Value: []byte(fmt.Sprintf("consensus-%d", i))},
		}
	}
	return units
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

// mustBuildTMHeaderForExplicitStateTest returns both the typed header and its
// packed Any form. Use it for tests that need both representations.
func mustBuildTMHeaderForExplicitStateTest(t *testing.T, trustedHeight uint64) (*tmclienttypes.Header, *codectypes.Any) {
	t.Helper()
	header := &tmclienttypes.Header{
		TrustedHeight: clienttypes.Height{RevisionHeight: trustedHeight},
	}
	anyHeader, err := codectypes.NewAnyWithValue(header)
	if err != nil {
		t.Fatalf("failed to pack tendermint header: %v", err)
	}
	return header, anyHeader
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
			nil,
			"07-tendermint-11",
			false,
			[]byte("signer"),
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
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 0).Header,
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
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 1).Header,
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

func TestExecuteExplicitStateSourceHeaderUnitStreamRejectsNilAndIncompleteBaseStateUnits(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	t.Cleanup(server.Stop)

	svc := &explicitStateSplitBoundaryServer{}
	elc.RegisterQueryServer(server, svc)
	elc.RegisterMsgServer(server, svc)
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

	unitStream := make(chan *ExplicitStateSourceHeaderUnitOrError, 4)
	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 0).Header,
		BaseState: &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 10},
			ClientState:    &codectypes.Any{TypeUrl: "client/10", Value: []byte("client-10")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/10", Value: []byte("consensus-10")},
		},
	}}
	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 1).Header,
		BaseState: nil,
	}}
	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 2).Header,
		BaseState: &ExplicitStateRef{
			PrevHeight: &clienttypes.Height{RevisionHeight: 12},
		},
	}}
	unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
		AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), 3).Header,
		BaseState: &ExplicitStateRef{
			PrevHeight:     &clienttypes.Height{RevisionHeight: 13},
			ClientState:    &codectypes.Any{TypeUrl: "client/13", Value: []byte("client-13")},
			ConsensusState: &codectypes.Any{TypeUrl: "consensus/13", Value: []byte("consensus-13")},
		},
	}}
	close(unitStream)

	pr := &Prover{
		config:           ProverConfig{ElcClientId: "07-tendermint-11"},
		lcpServiceClient: NewLCPServiceClient(conn),
	}
	results, err := pr.executeExplicitStateELCUpdateSourceHeaderUnitStream(
		context.Background(),
		unitStream,
		nil,
		"07-tendermint-11",
		false,
		[]byte("signer"),
	)
	if err == nil {
		t.Fatal("expected incomplete base-state unit to fail")
	}
	if len(results) != 0 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if svc.updateCalls != 0 {
		t.Fatalf("expected serial update-client fallback not to be used, got %d", svc.updateCalls)
	}
}

func TestUpdateELCForUpdateClientExplicitStateMatchesLegacyResults(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	svc := &explicitStateParityTestServer{}
	elc.RegisterQueryServer(server, svc)
	elc.RegisterMsgServer(server, svc)
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
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 11}},
	}
	activeEnclaveKey := &enclave.EnclaveKeyInfo{
		KeyInfo: &enclave.EnclaveKeyInfo_Ias{
			Ias: &enclave.IASEnclaveKeyInfo{
				EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
			},
		},
	}

	explicitResults, err := (&Prover{
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			headers:             headers,
			explicitStateChunks: mustExplicitStateSourceUnitsWithBaseStatesFromHeaders(t, headers...),
		},
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: activeEnclaveKey,
	}).updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		headers[len(headers)-1],
	)
	if err != nil {
		t.Fatalf("explicit updateELCForUpdateClient() error = %v", err)
	}

	legacyResults, err := (&Prover{
		config: ProverConfig{
			ElcClientId: "07-tendermint-11",
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			headers: headers,
		},
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: activeEnclaveKey,
	}).updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		headers[len(headers)-1],
	)
	if err != nil {
		t.Fatalf("legacy updateELCForUpdateClient() error = %v", err)
	}

	if svc.batchCalls != 1 {
		t.Fatalf("expected one explicit-state batch call, got %d", svc.batchCalls)
	}
	if svc.updateCalls != len(headers) {
		t.Fatalf("expected %d legacy update-client calls, got %d", len(headers), svc.updateCalls)
	}
	assertUpdateClientResultsEqual(t, explicitResults, legacyResults)
}

func TestIsExplicitStateBaseStateMismatchError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "wrapped grpc status",
			err:  fmt.Errorf("failed explicit-state update client batch: %w", status.Error(codes.Aborted, "BaseStateMismatch: invalid argument")),
			want: true,
		},
		{
			name: "grpc status",
			err:  status.Error(codes.Aborted, "BaseStateMismatch: invalid argument: descr=stored speculative base client_state mismatch"),
			want: true,
		},
		{
			name: "detail without aborted status",
			err:  fmt.Errorf("stored speculative base client_state mismatch: client_id=07-tendermint-11"),
			want: false,
		},
		{
			name: "other",
			err:  fmt.Errorf("SpeculativeExecutionFailed"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExplicitStateBaseStateMismatchError(tt.err); got != tt.want {
				t.Fatalf("isExplicitStateBaseStateMismatchError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryLCPCanonicalExplicitStateBase(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	svc := &explicitStateCanonicalRetryServer{}
	elc.RegisterQueryServer(server, svc)
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

	base, err := (&Prover{
		codec:            coreCodec,
		lcpServiceClient: NewLCPServiceClient(conn),
	}).queryLCPCanonicalExplicitStateBase(context.Background(), "07-tendermint-11")
	if err != nil {
		t.Fatalf("queryLCPCanonicalExplicitStateBase() error = %v", err)
	}
	if base == nil || base.Height.RevisionHeight != 7 {
		t.Fatalf("unexpected base height: %#v", base)
	}
	if base.ClientState == nil || base.ConsensusState == nil {
		t.Fatalf("expected packed base states: %#v", base)
	}
	if svc.queryCalls != 1 {
		t.Fatalf("unexpected query calls: %d", svc.queryCalls)
	}
}

func TestQueryExplicitStateBaseUsesOnChainCommittedHeight(t *testing.T) {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	lcptypes.RegisterInterfaces(interfaceRegistry)
	coreCodec := codec.NewProtoCodec(interfaceRegistry)

	onChainHeight := clienttypes.Height{RevisionHeight: 9}
	originProver := &fakeOriginProverWithInitialState{}
	chain := &fakeOnChainLCPChain{
		queryHeight:       clienttypes.Height{RevisionHeight: 100},
		clientStateHeight: onChainHeight,
		stateID:           []byte("on-chain-state-9"),
	}
	base, err := (&Prover{
		codec:        coreCodec,
		originProver: originProver,
	}).queryExplicitStateBase(context.Background(), chain, "07-tendermint-11")
	if err != nil {
		t.Fatalf("queryExplicitStateBase() error = %v", err)
	}
	if base == nil || base.Height.RevisionHeight != onChainHeight.RevisionHeight {
		t.Fatalf("unexpected base height: %#v", base)
	}
	if len(originProver.requestedHeights) != 1 || originProver.requestedHeights[0].GetRevisionHeight() != onChainHeight.RevisionHeight {
		t.Fatalf("expected origin prover to build base at on-chain height, got %#v", originProver.requestedHeights)
	}
	if len(chain.consensusQueries) != 1 || chain.consensusQueries[0].GetRevisionHeight() != onChainHeight.RevisionHeight {
		t.Fatalf("expected consensus query at on-chain height, got %#v", chain.consensusQueries)
	}
	var clientState ibcexported.ClientState
	if err := coreCodec.UnpackAny(base.ClientState, &clientState); err != nil {
		t.Fatalf("failed to unpack base client_state: %v", err)
	}
	if got := clientState.GetLatestHeight(); got.GetRevisionHeight() != onChainHeight.RevisionHeight {
		t.Fatalf("unexpected packed base client_state height: %v", got)
	}
}

func TestUpdateELCForUpdateClientRetriesExplicitStateFromCanonicalBase(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	svc := &explicitStateCanonicalRetryServer{}
	elc.RegisterQueryServer(server, svc)
	elc.RegisterMsgServer(server, svc)
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

	originProver := &fakeOriginProverWithBase{}
	results, err := (&Prover{
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec:            coreCodec,
		originProver:     originProver,
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: &enclave.EnclaveKeyInfo{
			KeyInfo: &enclave.EnclaveKeyInfo_Ias{
				Ias: &enclave.IASEnclaveKeyInfo{
					EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
				},
			},
		},
	}).updateELCForUpdateClient(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 1}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 10}},
	)
	if err != nil {
		t.Fatalf("updateELCForUpdateClient() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if svc.queryCalls != 2 {
		t.Fatalf("expected canonical state to be queried before each explicit-state attempt, got %d calls", svc.queryCalls)
	}
	if svc.batchCalls != 2 {
		t.Fatalf("expected speculative batch to be retried once, got %d calls", svc.batchCalls)
	}
	if len(originProver.bases) != 2 {
		t.Fatalf("expected two chunk provider calls, got %d", len(originProver.bases))
	}
	if originProver.bases[0].Height.RevisionHeight != 7 || originProver.bases[1].Height.RevisionHeight != 8 {
		t.Fatalf("unexpected canonical base heights: %#v", originProver.bases)
	}
}

func TestUpdateELCRetriesExplicitStateFromCanonicalBase(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	svc := &explicitStateCanonicalRetryServer{}
	elc.RegisterQueryServer(server, svc)
	elc.RegisterMsgServer(server, svc)
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

	originProver := &fakeOriginProverWithBase{
		fakeOriginProver: fakeOriginProver{
			headers: []core.Header{
				&tmclienttypes.Header{
					SignedHeader: &tmproto.SignedHeader{
						Header: &tmproto.Header{
							Height: 10,
						},
					},
				},
			},
		},
	}
	responses, err := (&Prover{
		config: ProverConfig{
			EnableExplicitStateUpdateClient: true,
		},
		codec:            coreCodec,
		originProver:     originProver,
		lcpServiceClient: NewLCPServiceClient(conn),
		activeEnclaveKey: &enclave.EnclaveKeyInfo{
			KeyInfo: &enclave.EnclaveKeyInfo_Ias{
				Ias: &enclave.IASEnclaveKeyInfo{
					EnclaveKeyAddress: common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
				},
			},
		},
	}).updateELC(
		context.Background(),
		"07-tendermint-11",
		false,
	)
	if err != nil {
		t.Fatalf("updateELC() error = %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("unexpected response count: %d", len(responses))
	}
	if svc.queryCalls != 3 {
		t.Fatalf("expected initial freshness query plus one canonical base query per explicit-state attempt, got %d calls", svc.queryCalls)
	}
	if svc.batchCalls != 2 {
		t.Fatalf("expected speculative batch to be retried once, got %d calls", svc.batchCalls)
	}
	if len(originProver.bases) != 2 {
		t.Fatalf("expected two chunk provider calls, got %d", len(originProver.bases))
	}
	if originProver.bases[0].Height.RevisionHeight != 8 || originProver.bases[1].Height.RevisionHeight != 9 {
		t.Fatalf("unexpected canonical base heights: %#v", originProver.bases)
	}
}

func assertUpdateClientResultsEqual(t *testing.T, got, want []*elcupdater_storage.UpdateClientResult) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("result length mismatch: got=%d want=%d", len(got), len(want))
	}
	for i := range got {
		if got[i] == nil || want[i] == nil {
			t.Fatalf("nil result at index %d: got=%#v want=%#v", i, got[i], want[i])
		}
		if !bytes.Equal(got[i].Message, want[i].Message) {
			t.Fatalf("message mismatch at index %d: got=%x want=%x", i, got[i].Message, want[i].Message)
		}
		if !bytes.Equal(got[i].Signature, want[i].Signature) {
			t.Fatalf("signature mismatch at index %d: got=%x want=%x", i, got[i].Signature, want[i].Signature)
		}
		if !bytes.Equal(got[i].Signer, want[i].Signer) {
			t.Fatalf("signer mismatch at index %d: got=%x want=%x", i, got[i].Signer, want[i].Signer)
		}
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
	explicitStateChunks := mustExplicitStateSourceUnitsWithBaseStatesFromHeaders(t, headers...)
	pr := &Prover{
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			headers:             headers,
			explicitStateChunks: explicitStateChunks,
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
	if captured.Units[0].BaseState == nil || captured.Units[0].BaseState.PrevHeight == nil || !captured.Units[0].BaseState.PrevHeight.EQ(*explicitStateChunks[0].BaseState.PrevHeight) {
		t.Fatalf("unexpected first base state: %#v", captured.Units[0].BaseState)
	}
	if captured.Units[1].BaseState == nil || captured.Units[1].BaseState.PrevHeight == nil || !captured.Units[1].BaseState.PrevHeight.EQ(*explicitStateChunks[1].BaseState.PrevHeight) {
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
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			headers: headers,
			explicitStateChunks: []*ExplicitStateSourceHeaderUnit{
				{
					AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10),
					BaseState: baseStates[0],
				},
				{
					AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 10),
					BaseState: baseStates[1],
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
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			headers:             headers,
			explicitStateChunks: mustExplicitStateSourceUnitsWithBaseStatesFromHeaders(t, headers...),
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

func TestUpdateELCForUpdateClientReturnsErrorWhenBatchRPCUnavailable(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	unsupportedBatchServer := &unsupportedSpeculativeBatchServer{}
	elc.RegisterQueryServer(server, unsupportedBatchServer)
	elc.RegisterMsgServer(server, unsupportedBatchServer)
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
		config: ProverConfig{
			ElcClientId:                     "07-tendermint-11",
			EnableExplicitStateUpdateClient: true,
		},
		codec: coreCodec,
		originProver: fakeOriginProver{
			explicitStateChunks: []*ExplicitStateSourceHeaderUnit{
				{
					AnyHeader: anyHeader,
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
	if err == nil {
		t.Fatal("expected updateELCForUpdateClient() to fail when speculative batch RPC is unavailable")
	}
	if unsupportedBatchServer.batchCalls != 1 {
		t.Fatalf("expected speculative batch to be attempted once, got %d", unsupportedBatchServer.batchCalls)
	}
	if unsupportedBatchServer.updateCalls != 0 {
		t.Fatalf("expected serial update-client fallback not to be used, got %d", unsupportedBatchServer.updateCalls)
	}
	if len(results) != 0 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestExecuteExplicitStateSourceHeaderUnitStreamCancelsBlockedSourceProducerOnBatchError(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	secondSendAttempted := make(chan struct{})
	elc.RegisterMsgServer(server, &blockingSpeculativeBatchErrorServer{
		secondSendAttempted: secondSendAttempted,
	})
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

	unitStream := make(chan *ExplicitStateSourceHeaderUnitOrError)
	producerCtx, producerCancel := context.WithCancel(context.Background())
	defer producerCancel()
	producerStoppedAt := make(chan int, 1)
	go func() {
		defer close(unitStream)
		for i := 0; i < 10; i++ {
			if i == 1 {
				close(secondSendAttempted)
			}
			select {
			case unitStream <- &ExplicitStateSourceHeaderUnitOrError{Unit: &ExplicitStateSourceHeaderUnit{
				AnyHeader: makeSpeculativeBatchTestUpdate("07-tendermint-11", []byte("signer"), i).Header,
				BaseState: &ExplicitStateRef{
					PrevHeight:     &clienttypes.Height{RevisionHeight: uint64(10 + i)},
					ClientState:    &codectypes.Any{TypeUrl: fmt.Sprintf("client/%d", i), Value: []byte("client")},
					ConsensusState: &codectypes.Any{TypeUrl: fmt.Sprintf("consensus/%d", i), Value: []byte("consensus")},
				},
			}}:
			case <-producerCtx.Done():
				producerStoppedAt <- i
				return
			}
		}
		producerStoppedAt <- -1
	}()

	var cancelWaitErr error
	producerStoppedIndex := -2
	cancelAndWaitForProducer := func() {
		producerCancel()
		select {
		case producerStoppedIndex = <-producerStoppedAt:
		case <-time.After(2 * time.Second):
			cancelWaitErr = fmt.Errorf("producer did not stop after cancellation")
		}
	}

	pr := &Prover{
		config: ProverConfig{
			ElcClientId:                        "07-tendermint-11",
			MaxSpeculativeBatchUnitsPerRequest: 1,
		},
		lcpServiceClient: NewLCPServiceClient(conn),
	}
	results, err := pr.executeExplicitStateELCUpdateSourceHeaderUnitStream(
		context.Background(),
		unitStream,
		nil,
		"07-tendermint-11",
		false,
		[]byte("signer"),
	)
	cancelAndWaitForProducer()
	drainExplicitStateSourceHeaderUnitStreamDiscard(unitStream)
	if err == nil {
		t.Fatal("expected speculative batch error")
	}
	if len(results) != 0 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if cancelWaitErr != nil {
		t.Fatal(cancelWaitErr)
	}
	if producerStoppedIndex != 1 {
		t.Fatalf("expected producer to be cancelled while sending unit 1, got %d", producerStoppedIndex)
	}
}

func TestUpdateELCForUpdateClientUsesLegacyWhenExplicitStateNotEnabled(t *testing.T) {
	if err := ylog.InitLogger("error", "text", "null", false); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	unsupportedBatchServer := &unsupportedSpeculativeBatchServer{}
	elc.RegisterQueryServer(server, unsupportedBatchServer)
	elc.RegisterMsgServer(server, unsupportedBatchServer)
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
		config: ProverConfig{
			ElcClientId: "07-tendermint-11",
		},
		codec: coreCodec,
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
	if unsupportedBatchServer.batchCalls != 0 {
		t.Fatalf("expected speculative batch to be disabled, got %d calls", unsupportedBatchServer.batchCalls)
	}
	if unsupportedBatchServer.updateCalls != 1 {
		t.Fatalf("expected serial update-client to be used once, got %d", unsupportedBatchServer.updateCalls)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestCollectExplicitStateChunkSourceHeaderUnitStreamForUpdateUsesChunkProvider(t *testing.T) {
	expectedBaseState := &ExplicitStateRef{
		PrevHeight:  &clienttypes.Height{RevisionHeight: 12},
		PrevStateId: []byte("state-12"),
	}
	expected := []*ExplicitStateSourceHeaderUnit{
		{
			AnyHeader: mustPackTMHeaderForExplicitStateTest(t, 12),
			BaseState: expectedBaseState,
		},
	}
	pr := &Prover{
		originProver: fakeOriginProver{
			explicitStateChunks: expected,
		},
	}

	unitStream, err := pr.collectExplicitStateChunkSourceHeaderUnitStreamForUpdate(
		context.Background(),
		elcupdater.NewMockChain("counterparty", clienttypes.Height{RevisionHeight: 7}),
		&tmclienttypes.Header{TrustedHeight: clienttypes.Height{RevisionHeight: 12}},
		nil,
	)
	if err != nil {
		t.Fatalf("collectExplicitStateChunkSourceHeaderUnitStreamForUpdate() error = %v", err)
	}
	item, ok := <-unitStream
	if !ok {
		t.Fatal("expected one source unit")
	}
	unit, err := explicitStateSourceHeaderUnitFromStreamItemOrError(item, 0)
	if err != nil {
		t.Fatalf("explicitStateSourceHeaderUnitFromStreamItemOrError() error = %v", err)
	}
	if unit != expected[0] {
		t.Fatalf("expected chunk provider result to be used directly: %#v", unit)
	}
	if item, ok := <-unitStream; ok {
		t.Fatalf("unexpected extra source unit: %#v", item)
	}
}
