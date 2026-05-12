package relay

import "github.com/datachainlab/lcp-go/relay/elc"

type ExplicitStateRef = elc.ExplicitStateRef
type ObservedStateTransition = elc.ObservedStateTransition
type StitchedSpeculativeUpdateClientUnitResult = elc.StitchedSpeculativeUpdateClientUnitResult
type ExecuteSpeculativeUpdateClientBatchResponse = elc.ExecuteSpeculativeUpdateClientBatchResponse

type SpeculativeUpdateClientUnit struct {
	UnitId    string
	Update    *elc.MsgUpdateClient
	BaseState *ExplicitStateRef
}

type ExecuteSpeculativeUpdateClientBatchRequest struct {
	ClientId string
	Units    []*SpeculativeUpdateClientUnit
}
