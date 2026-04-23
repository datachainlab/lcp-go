package relay

import (
	"testing"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
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
