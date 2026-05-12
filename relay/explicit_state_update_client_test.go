package relay

import (
	"fmt"
	"testing"
	"time"

	gogoproto "github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclienttypes "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
)

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

func TestShouldUseExplicitStateUpdateClientUsesProverConfig(t *testing.T) {
	if got := (&Prover{}).shouldUseExplicitStateUpdateClient(); !got {
		t.Fatal("expected explicit-state update client to be enabled by default")
	}

	pr := &Prover{
		config: ProverConfig{DisableExplicitStateUpdateClient: true},
	}
	if got := pr.shouldUseExplicitStateUpdateClient(); got {
		t.Fatal("expected explicit-state update client to be disabled by config")
	}
}

func TestProverConfigDisableExplicitStateUpdateClientRoundTrip(t *testing.T) {
	bz, err := gogoproto.Marshal(&ProverConfig{DisableExplicitStateUpdateClient: true})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got ProverConfig
	if err := gogoproto.Unmarshal(bz, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.DisableExplicitStateUpdateClient {
		t.Fatal("expected disable_explicit_state_update_client to round-trip")
	}
}

func buildExplicitStateRefFromCanonicalState(
	clientState ibcexported.ClientState,
	consensusState ibcexported.ConsensusState,
) (*ExplicitStateRef, error) {
	ref := &ExplicitStateRef{}
	if clientState == nil {
		return nil, fmt.Errorf("client state must not be nil")
	}
	latestHeight, ok := clientState.GetLatestHeight().(clienttypes.Height)
	if !ok {
		return nil, fmt.Errorf("unsupported latest height type for explicit state ref: %T", clientState.GetLatestHeight())
	}
	if !latestHeight.IsZero() {
		h := latestHeight
		ref.PrevHeight = &h
	}

	if cs, ok := consensusState.(*lcptypes.ConsensusState); ok && cs != nil && len(cs.StateId) > 0 {
		ref.PrevStateId = append([]byte(nil), cs.StateId...)
	}

	anyClientState, err := clienttypes.PackClientState(clientState)
	if err != nil {
		return nil, fmt.Errorf("failed to pack client state for explicit state payload: %w", err)
	}
	ref.ClientState = anyClientState

	anyConsensusState, err := clienttypes.PackConsensusState(consensusState)
	if err != nil {
		return nil, fmt.Errorf("failed to pack consensus state for explicit state ref: %w", err)
	}
	ref.ConsensusState = anyConsensusState
	return ref, nil
}
