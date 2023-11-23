package relay

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"reflect"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/hyperledger-labs/yui-relayer/core"
)

func (pr *Prover) restoreELCState(ctx context.Context, counterparty core.FinalityAwareChain, height uint64) error {
	if err := pr.initServiceClient(); err != nil {
		return err
	}

	// ensure the client does not exist in the LCP service
	_, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{
		ClientId: pr.config.ElcClientId,
	})
	if err == nil {
		return fmt.Errorf("client '%v' already exists", pr.config.ElcClientId)
	}

	cplatestHeight, err := counterparty.LatestHeight()
	if err != nil {
		return err
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(context.TODO(), cplatestHeight))
	if err != nil {
		return err
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return err
	}

	var restoreHeight ibcexported.Height
	if height == 0 {
		restoreHeight = cs.GetLatestHeight()
	} else {
		restoreHeight = clienttypes.NewHeight(cs.GetLatestHeight().GetRevisionNumber(), height)
	}

	log.Printf("try to restore ELC state: height=%v", restoreHeight)

	counterpartyConsRes, err := counterparty.QueryClientConsensusState(core.NewQueryContext(context.TODO(), cplatestHeight), restoreHeight)
	if err != nil {
		return err
	}
	var cons ibcexported.ConsensusState
	if err := pr.codec.UnpackAny(counterpartyConsRes.ConsensusState, &cons); err != nil {
		return err
	}

	clientState := cs.(*lcptypes.ClientState)
	consensusState := cons.(*lcptypes.ConsensusState)

	// Validate the prover config matches the counterparty's client state

	if !bytes.Equal(pr.config.GetMrenclave(), clientState.Mrenclave) {
		return fmt.Errorf("mrenclave mismatch: expected %v, but got %v", pr.config.GetMrenclave(), clientState.Mrenclave)
	}
	if pr.config.KeyExpiration != clientState.KeyExpiration {
		return fmt.Errorf("key expiration mismatch: expected %v, but got %v", pr.config.KeyExpiration, clientState.KeyExpiration)
	}
	if len(pr.config.AllowedQuoteStatuses) != len(clientState.AllowedQuoteStatuses) {
		return fmt.Errorf("allowed quote statuses mismatch: expected %v, but got %v", pr.config.AllowedQuoteStatuses, clientState.AllowedQuoteStatuses)
	}
	if !reflect.DeepEqual(pr.config.AllowedQuoteStatuses, clientState.AllowedQuoteStatuses) {
		return fmt.Errorf("allowed advisory ids mismatch: expected %v, but got %v", pr.config.AllowedAdvisoryIds, clientState.AllowedAdvisoryIds)
	}
	if !reflect.DeepEqual(pr.config.AllowedAdvisoryIds, clientState.AllowedAdvisoryIds) {
		return fmt.Errorf("allowed advisory ids mismatch: expected %v, but got %v", pr.config.AllowedAdvisoryIds, clientState.AllowedAdvisoryIds)
	}

	originClientState, originConsensusState, err := pr.originProver.CreateInitialLightClientState(clientState.LatestHeight)
	if err != nil {
		return err
	}
	originAnyClientState, err := clienttypes.PackClientState(originClientState)
	if err != nil {
		return err
	}
	originAnyConsensusState, err := clienttypes.PackConsensusState(originConsensusState)
	if err != nil {
		return err
	}
	tmpEKI, err := pr.selectNewEnclaveKey(context.TODO())
	if err != nil {
		return err
	}
	res, err := pr.lcpServiceClient.CreateClient(context.TODO(), &elc.MsgCreateClient{
		ClientState:    originAnyClientState,
		ConsensusState: originAnyConsensusState,
		Signer:         tmpEKI.EnclaveKeyAddress,
	})
	if err != nil {
		return err
	}

	// Ensure the restored state is correct

	commitment, err := lcptypes.EthABIDecodeHeaderedCommitment(res.Commitment)
	if err != nil {
		return err
	}
	ucc, err := commitment.GetUpdateClientCommitment()
	if err != nil {
		return err
	}
	if !ucc.NewStateID.EqualBytes(consensusState.StateId) {
		return fmt.Errorf("unexpected state id: expected %v, but got %v", ucc.NewStateID, consensusState.StateId)
	}
	if !ucc.NewHeight.EQ(restoreHeight) {
		return fmt.Errorf("unexpected height: expected %v, but got %v", restoreHeight, ucc.NewHeight)
	}

	// TODO relayer should update res.ClientId in the config
	if pr.config.ElcClientId != res.ClientId {
		return fmt.Errorf("you must specify '%v' as elc_client_id, but got %v", res.ClientId, pr.config.ElcClientId)
	}

	log.Printf("successfully restored ELC state: client_id=%v, state_id=%v, height=%v", res.ClientId, ucc.NewStateID, ucc.NewHeight)

	return nil
}
