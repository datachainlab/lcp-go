package relay

import (
	"bytes"
	"strings"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	gogoproto "github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
)

func TestShouldUseExplicitStateUpdateClientRequiresConfigAndProvider(t *testing.T) {
	if got := (&Prover{}).shouldUseExplicitStateUpdateClient(); got {
		t.Fatal("expected explicit-state update client to be disabled by default")
	}

	withoutProvider := &Prover{
		config: ProverConfig{EnableExplicitStateUpdateClient: true},
	}
	if got := withoutProvider.shouldUseExplicitStateUpdateClient(); got {
		t.Fatal("expected explicit-state update client to require an ExplicitStateChunkProvider")
	}

	withProvider := &Prover{
		config:       ProverConfig{EnableExplicitStateUpdateClient: true},
		originProver: fakeOriginProver{},
	}
	if got := withProvider.shouldUseExplicitStateUpdateClient(); !got {
		t.Fatal("expected explicit-state update client to be enabled when config and provider are present")
	}
}

func TestBindFirstUnitToExplicitStateBase(t *testing.T) {
	baseHeight := clienttypes.Height{RevisionNumber: 0, RevisionHeight: 10}
	mkUnit := func(prevHeight *clienttypes.Height, prevStateID []byte) *ExplicitStateSourceHeaderUnit {
		return &ExplicitStateSourceHeaderUnit{
			BaseState: &ExplicitStateRef{
				PrevHeight:     prevHeight,
				PrevStateId:    prevStateID,
				ClientState:    &codectypes.Any{TypeUrl: "client", Value: []byte("client-10")},
				ConsensusState: &codectypes.Any{TypeUrl: "consensus", Value: []byte("consensus-10")},
			},
		}
	}

	t.Run("nil base is a no-op", func(t *testing.T) {
		unit := mkUnit(&baseHeight, nil)
		if err := bindFirstUnitToExplicitStateBase(unit, nil); err != nil {
			t.Fatalf("bindFirstUnitToExplicitStateBase() error = %v", err)
		}
		if unit.BaseState.PrevStateId != nil {
			t.Fatal("expected prev_state_id to stay empty for nil base")
		}
	})

	t.Run("injects committed state id into first unit", func(t *testing.T) {
		unit := mkUnit(&baseHeight, nil)
		base := &ExplicitStateBase{Height: baseHeight, StateId: []byte("state-10")}
		if err := bindFirstUnitToExplicitStateBase(unit, base); err != nil {
			t.Fatalf("bindFirstUnitToExplicitStateBase() error = %v", err)
		}
		if !bytes.Equal(unit.BaseState.PrevStateId, []byte("state-10")) {
			t.Fatalf("expected injected prev_state_id, got %q", unit.BaseState.PrevStateId)
		}
	})

	t.Run("keeps matching provider prev_state_id", func(t *testing.T) {
		unit := mkUnit(&baseHeight, []byte("state-10"))
		base := &ExplicitStateBase{Height: baseHeight, StateId: []byte("state-10")}
		if err := bindFirstUnitToExplicitStateBase(unit, base); err != nil {
			t.Fatalf("bindFirstUnitToExplicitStateBase() error = %v", err)
		}
	})

	t.Run("rejects prev_state_id mismatch", func(t *testing.T) {
		unit := mkUnit(&baseHeight, []byte("state-other"))
		base := &ExplicitStateBase{Height: baseHeight, StateId: []byte("state-10")}
		err := bindFirstUnitToExplicitStateBase(unit, base)
		if err == nil || !strings.Contains(err.Error(), "prev_state_id mismatch") {
			t.Fatalf("expected prev_state_id mismatch error, got %v", err)
		}
	})

	t.Run("rejects base height mismatch", func(t *testing.T) {
		otherHeight := clienttypes.Height{RevisionNumber: 0, RevisionHeight: 11}
		unit := mkUnit(&otherHeight, nil)
		base := &ExplicitStateBase{Height: baseHeight}
		err := bindFirstUnitToExplicitStateBase(unit, base)
		if err == nil || !strings.Contains(err.Error(), "base height mismatch") {
			t.Fatalf("expected base height mismatch error, got %v", err)
		}
	})
}

func TestProverConfigEnableExplicitStateUpdateClientRoundTrip(t *testing.T) {
	bz, err := gogoproto.Marshal(&ProverConfig{EnableExplicitStateUpdateClient: true})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got ProverConfig
	if err := gogoproto.Unmarshal(bz, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.EnableExplicitStateUpdateClient {
		t.Fatal("expected enable_explicit_state_update_client to round-trip")
	}
}
