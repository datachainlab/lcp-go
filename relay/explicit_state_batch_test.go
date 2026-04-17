package relay

import (
	"testing"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/elc"
)

func TestBuildLinearSpeculativeUpdateClientBatch(t *testing.T) {
	updates := []*elc.MsgUpdateClient{
		{ClientId: "client-0"},
		{ClientId: "client-0"},
	}
	baseStates := []*ExplicitStateRef{
		nil,
		{
			PrevHeight:  &clienttypes.Height{RevisionNumber: 0, RevisionHeight: 11},
			PrevStateId: []byte("post-0"),
		},
	}

	req, err := buildLinearSpeculativeUpdateClientBatch("client-0", updates, baseStates)
	if err != nil {
		t.Fatalf("buildLinearSpeculativeUpdateClientBatch() error = %v", err)
	}

	if req.ClientId != "client-0" {
		t.Fatalf("unexpected client id: %s", req.ClientId)
	}
	if len(req.Units) != 2 {
		t.Fatalf("unexpected unit count: %d", len(req.Units))
	}
	if req.Units[0].UnitId != "unit-0000" || len(req.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected first unit: %+v", req.Units[0])
	}
	if req.Units[1].UnitId != "unit-0001" {
		t.Fatalf("unexpected second unit id: %s", req.Units[1].UnitId)
	}
	if len(req.Units[1].DependencyIds) != 1 || req.Units[1].DependencyIds[0] != "unit-0000" {
		t.Fatalf("unexpected second unit dependencies: %+v", req.Units[1].DependencyIds)
	}
	if req.Units[1].BaseState == nil || req.Units[1].BaseState.PrevHeight == nil {
		t.Fatalf("expected second unit base state")
	}
}

func TestBuildLinearSpeculativeUpdateClientBatchRejectsLengthMismatch(t *testing.T) {
	_, err := buildLinearSpeculativeUpdateClientBatch(
		"client-0",
		[]*elc.MsgUpdateClient{{ClientId: "client-0"}},
		nil,
	)
	if err == nil {
		t.Fatal("expected error for mismatched lengths")
	}
}

func TestBuildLaneSpeculativeUpdateClientBatch(t *testing.T) {
	req, err := buildLaneSpeculativeUpdateClientBatch(
		"client-0",
		[][]*elc.MsgUpdateClient{
			{
				{ClientId: "client-0"},
				{ClientId: "client-0"},
			},
			{
				{ClientId: "client-0"},
			},
		},
		[][]*ExplicitStateRef{
			{
				nil,
				{PrevHeight: &clienttypes.Height{RevisionNumber: 0, RevisionHeight: 11}},
			},
			{
				nil,
			},
		},
	)
	if err != nil {
		t.Fatalf("buildLaneSpeculativeUpdateClientBatch() error = %v", err)
	}
	if len(req.Units) != 3 {
		t.Fatalf("unexpected unit count: %d", len(req.Units))
	}
	if len(req.Units[0].DependencyIds) != 0 {
		t.Fatalf("unexpected first unit dependencies: %v", req.Units[0].DependencyIds)
	}
	if len(req.Units[1].DependencyIds) != 1 || req.Units[1].DependencyIds[0] != "unit-0000" {
		t.Fatalf("unexpected second unit dependencies: %v", req.Units[1].DependencyIds)
	}
	if len(req.Units[2].DependencyIds) != 0 {
		t.Fatalf("unexpected second lane root dependencies: %v", req.Units[2].DependencyIds)
	}
}
