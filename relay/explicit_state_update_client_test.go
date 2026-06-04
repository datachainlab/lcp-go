package relay

import (
	"testing"

	gogoproto "github.com/cosmos/gogoproto/proto"
)

func TestShouldUseExplicitStateUpdateClientUsesProverConfig(t *testing.T) {
	if got := (&Prover{}).shouldUseExplicitStateUpdateClient(); got {
		t.Fatal("expected explicit-state update client to be disabled by default")
	}

	pr := &Prover{
		config: ProverConfig{EnableExplicitStateUpdateClient: true},
	}
	if got := pr.shouldUseExplicitStateUpdateClient(); !got {
		t.Fatal("expected explicit-state update client to be enabled by config")
	}
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
