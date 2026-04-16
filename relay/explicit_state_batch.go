package relay

import (
	"context"
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"google.golang.org/grpc"
)

const executeSpeculativeUpdateClientBatchMethod = "/lcp.service.elc.v1.Msg/ExecuteSpeculativeUpdateClientBatch"

type ExplicitStateRef struct {
	PrevHeight     *clienttypes.Height `protobuf:"bytes,1,opt,name=prev_height,json=prevHeight,proto3" json:"prev_height,omitempty"`
	PrevStateId    []byte              `protobuf:"bytes,2,opt,name=prev_state_id,json=prevStateId,proto3" json:"prev_state_id,omitempty"`
	ClientState    *codectypes.Any     `protobuf:"bytes,3,opt,name=client_state,json=clientState,proto3" json:"client_state,omitempty"`
	ConsensusState *codectypes.Any     `protobuf:"bytes,4,opt,name=consensus_state,json=consensusState,proto3" json:"consensus_state,omitempty"`
}

func (m *ExplicitStateRef) Reset()         { *m = ExplicitStateRef{} }
func (m *ExplicitStateRef) String() string { return proto.CompactTextString(m) }
func (*ExplicitStateRef) ProtoMessage()    {}

type SpeculativeUpdateClientUnit struct {
	UnitId        string               `protobuf:"bytes,1,opt,name=unit_id,json=unitId,proto3" json:"unit_id,omitempty"`
	Update        *elc.MsgUpdateClient `protobuf:"bytes,2,opt,name=update,proto3" json:"update,omitempty"`
	BaseState     *ExplicitStateRef    `protobuf:"bytes,3,opt,name=base_state,json=baseState,proto3" json:"base_state,omitempty"`
	DependencyIds []string             `protobuf:"bytes,4,rep,name=dependency_ids,json=dependencyIds,proto3" json:"dependency_ids,omitempty"`
}

func (m *SpeculativeUpdateClientUnit) Reset()         { *m = SpeculativeUpdateClientUnit{} }
func (m *SpeculativeUpdateClientUnit) String() string { return proto.CompactTextString(m) }
func (*SpeculativeUpdateClientUnit) ProtoMessage()    {}

type ExecuteSpeculativeUpdateClientBatchRequest struct {
	ClientId string                         `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Units    []*SpeculativeUpdateClientUnit `protobuf:"bytes,2,rep,name=units,proto3" json:"units,omitempty"`
}

func (m *ExecuteSpeculativeUpdateClientBatchRequest) Reset() {
	*m = ExecuteSpeculativeUpdateClientBatchRequest{}
}
func (m *ExecuteSpeculativeUpdateClientBatchRequest) String() string {
	return proto.CompactTextString(m)
}
func (*ExecuteSpeculativeUpdateClientBatchRequest) ProtoMessage() {}

type ObservedStateTransition struct {
	PrevHeight  *clienttypes.Height `protobuf:"bytes,1,opt,name=prev_height,json=prevHeight,proto3" json:"prev_height,omitempty"`
	PrevStateId []byte              `protobuf:"bytes,2,opt,name=prev_state_id,json=prevStateId,proto3" json:"prev_state_id,omitempty"`
	PostHeight  *clienttypes.Height `protobuf:"bytes,3,opt,name=post_height,json=postHeight,proto3" json:"post_height,omitempty"`
	PostStateId []byte              `protobuf:"bytes,4,opt,name=post_state_id,json=postStateId,proto3" json:"post_state_id,omitempty"`
}

func (m *ObservedStateTransition) Reset()         { *m = ObservedStateTransition{} }
func (m *ObservedStateTransition) String() string { return proto.CompactTextString(m) }
func (*ObservedStateTransition) ProtoMessage()    {}

type StitchedSpeculativeUpdateClientUnitResult struct {
	Response           *elc.MsgUpdateClientResponse `protobuf:"bytes,1,opt,name=response,proto3" json:"response,omitempty"`
	ObservedTransition *ObservedStateTransition     `protobuf:"bytes,2,opt,name=observed_transition,json=observedTransition,proto3" json:"observed_transition,omitempty"`
}

func (m *StitchedSpeculativeUpdateClientUnitResult) Reset() {
	*m = StitchedSpeculativeUpdateClientUnitResult{}
}
func (m *StitchedSpeculativeUpdateClientUnitResult) String() string {
	return proto.CompactTextString(m)
}
func (*StitchedSpeculativeUpdateClientUnitResult) ProtoMessage() {}

type ExecuteSpeculativeUpdateClientBatchResponse struct {
	ClientId string                                       `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Units    []*StitchedSpeculativeUpdateClientUnitResult `protobuf:"bytes,2,rep,name=units,proto3" json:"units,omitempty"`
}

func (m *ExecuteSpeculativeUpdateClientBatchResponse) Reset() {
	*m = ExecuteSpeculativeUpdateClientBatchResponse{}
}
func (m *ExecuteSpeculativeUpdateClientBatchResponse) String() string {
	return proto.CompactTextString(m)
}
func (*ExecuteSpeculativeUpdateClientBatchResponse) ProtoMessage() {}

func executeSpeculativeUpdateClientBatch(
	ctx context.Context,
	client LCPServiceClient,
	in *ExecuteSpeculativeUpdateClientBatchRequest,
	opts ...grpc.CallOption,
) (*ExecuteSpeculativeUpdateClientBatchResponse, error) {
	out := new(ExecuteSpeculativeUpdateClientBatchResponse)
	if err := client.conn.Invoke(ctx, executeSpeculativeUpdateClientBatchMethod, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func executeSpeculativeUpdateClientBatchStream(
	ctx context.Context,
	client LCPServiceClient,
	in *ExecuteSpeculativeUpdateClientBatchRequest,
) (*ExecuteSpeculativeUpdateClientBatchResponse, error) {
	stream, err := client.ExecuteSpeculativeUpdateClientBatchStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call ExecuteSpeculativeUpdateClientBatchStream: %w", err)
	}
	if err := stream.Send(&elc.MsgExecuteSpeculativeUpdateClientBatchStreamChunk{
		Chunk: &elc.MsgExecuteSpeculativeUpdateClientBatchStreamChunk_Init{
			Init: &elc.ExecuteSpeculativeUpdateClientBatchStreamInit{
				ClientId: in.ClientId,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send speculative batch init: %w", err)
	}
	for i, unit := range in.Units {
		if err := stream.Send(&elc.MsgExecuteSpeculativeUpdateClientBatchStreamChunk{
			Chunk: &elc.MsgExecuteSpeculativeUpdateClientBatchStreamChunk_Unit{
				Unit: encodeSpeculativeUpdateClientUnit(unit),
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to send speculative batch unit: index=%d, %w", i, err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	return decodeSpeculativeUpdateClientBatchResponse(resp), nil
}

func encodeSpeculativeUpdateClientUnit(unit *SpeculativeUpdateClientUnit) *elc.SpeculativeUpdateClientUnit {
	if unit == nil {
		return nil
	}
	return &elc.SpeculativeUpdateClientUnit{
		UnitId:        unit.UnitId,
		Update:        *unit.Update,
		BaseState:     *encodeExplicitStateRef(unit.BaseState),
		DependencyIds: append([]string(nil), unit.DependencyIds...),
	}
}

func encodeExplicitStateRef(ref *ExplicitStateRef) *elc.ExplicitStateRef {
	if ref == nil {
		return nil
	}
	return &elc.ExplicitStateRef{
		PrevHeight:     ref.PrevHeight,
		PrevStateId:    append([]byte(nil), ref.PrevStateId...),
		ClientState:    ref.ClientState,
		ConsensusState: ref.ConsensusState,
	}
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

func decodeSpeculativeUpdateClientBatchResponse(resp *elc.ExecuteSpeculativeUpdateClientBatchResponse) *ExecuteSpeculativeUpdateClientBatchResponse {
	if resp == nil {
		return nil
	}
	units := make([]*StitchedSpeculativeUpdateClientUnitResult, 0, len(resp.Units))
	for _, unit := range resp.Units {
		if unit == nil {
			units = append(units, nil)
			continue
		}
		units = append(units, &StitchedSpeculativeUpdateClientUnitResult{
			Response:           &unit.Response,
			ObservedTransition: decodeObservedStateTransition(&unit.ObservedTransition),
		})
	}
	return &ExecuteSpeculativeUpdateClientBatchResponse{
		ClientId: resp.ClientId,
		Units:    units,
	}
}

func decodeObservedStateTransition(transition *elc.ObservedStateTransition) *ObservedStateTransition {
	if transition == nil {
		return nil
	}
	return &ObservedStateTransition{
		PrevHeight:  transition.PrevHeight,
		PrevStateId: append([]byte(nil), transition.PrevStateId...),
		PostHeight:  &transition.PostHeight,
		PostStateId: append([]byte(nil), transition.PostStateId...),
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
