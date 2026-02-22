package relay

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
)

type testSDKMsg struct {
	Payload []byte `protobuf:"bytes,1,opt,name=payload,proto3"`
}

func (m *testSDKMsg) Reset()         { *m = testSDKMsg{} }
func (m *testSDKMsg) String() string { return "testSDKMsg" }
func (*testSDKMsg) ProtoMessage()    {}

func newTestMsg(payloadLen int) sdk.Msg {
	return &testSDKMsg{Payload: make([]byte, payloadLen)}
}

func marshalMsgSize(t *testing.T, msg sdk.Msg) uint64 {
	t.Helper()
	bz, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal test msg: %v", err)
	}
	return uint64(len(bz))
}

func TestSplitMsgsByEstimatedSize_BatchSplit(t *testing.T) {
	msgs := []sdk.Msg{
		newTestMsg(10),
		newTestMsg(20),
		newTestMsg(30),
	}
	maxBatchMsgBytes := marshalMsgSize(t, msgs[0]) + marshalMsgSize(t, msgs[1])

	batches, err := splitMsgsByEstimatedSize(msgs, maxBatchMsgBytes)
	if err != nil {
		t.Fatalf("splitMsgsByEstimatedSize returned error: %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(batches))
	}
	if len(batches[0].msgs) != 2 {
		t.Fatalf("expected first batch size=2, got %d", len(batches[0].msgs))
	}
	if len(batches[1].msgs) != 1 {
		t.Fatalf("expected second batch size=1, got %d", len(batches[1].msgs))
	}
}

func TestSplitMsgsByEstimatedSize_OversizedSingleMessage(t *testing.T) {
	msgs := []sdk.Msg{
		newTestMsg(128),
		newTestMsg(1),
	}
	oversized := marshalMsgSize(t, msgs[0])
	maxBatchMsgBytes := oversized - 1

	batches, err := splitMsgsByEstimatedSize(msgs, maxBatchMsgBytes)
	if err != nil {
		t.Fatalf("splitMsgsByEstimatedSize returned error: %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(batches))
	}
	if len(batches[0].msgs) != 1 || len(batches[1].msgs) != 1 {
		t.Fatalf("expected both batches to have exactly one message, got %d and %d", len(batches[0].msgs), len(batches[1].msgs))
	}
	if batches[0].estimatedMsgBytes != oversized {
		t.Fatalf("expected oversized batch bytes=%d, got %d", oversized, batches[0].estimatedMsgBytes)
	}
}

func TestSplitMsgsByEstimatedSize_FinalFlush(t *testing.T) {
	msgs := []sdk.Msg{
		newTestMsg(10),
		newTestMsg(11),
		newTestMsg(12),
	}
	var sum uint64
	for _, msg := range msgs {
		sum += marshalMsgSize(t, msg)
	}

	batches, err := splitMsgsByEstimatedSize(msgs, sum+1)
	if err != nil {
		t.Fatalf("splitMsgsByEstimatedSize returned error: %v", err)
	}
	if len(batches) != 1 {
		t.Fatalf("expected a single batch, got %d", len(batches))
	}
	if len(batches[0].msgs) != len(msgs) {
		t.Fatalf("expected %d messages in the final batch, got %d", len(msgs), len(batches[0].msgs))
	}
}

func TestSplitMsgsByEstimatedSize_InvalidMaxBatchSize(t *testing.T) {
	_, err := splitMsgsByEstimatedSize([]sdk.Msg{newTestMsg(1)}, 0)
	if err == nil {
		t.Fatal("expected error when maxBatchMsgBytes is 0, got nil")
	}
}
