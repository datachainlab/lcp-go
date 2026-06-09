package relay

import (
	"testing"

	gogoproto "github.com/cosmos/gogoproto/proto"
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
