package relay

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/hyperledger-labs/yui-relayer/core"
)

func (pr *Prover) restoreELC(ctx context.Context, counterparty core.FinalityAwareChain, elcClientID string, height uint64) error {
	// ensure the client does not exist in the LCP service
	if res, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{
		ClientId: elcClientID,
	}); err != nil {
		return fmt.Errorf("failed to query ELC: elc_client_id=%v %w", elcClientID, err)
	} else if res.Found {
		return fmt.Errorf("client '%v' already exists", elcClientID)
	}

	cplatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return err
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, cplatestHeight))
	if err != nil {
		return fmt.Errorf("failed to query client state: height=%v %w", cplatestHeight, err)
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return fmt.Errorf("failed to unpack client state: client_state=%v %w", counterpartyClientRes.ClientState, err)
	}

	var restoreHeight ibcexported.Height
	if height == 0 {
		restoreHeight = cs.GetLatestHeight()
	} else {
		restoreHeight = clienttypes.NewHeight(cs.GetLatestHeight().GetRevisionNumber(), height)
	}

	pr.getLogger().Info("try to restore ELC state", "height", restoreHeight)

	counterpartyConsRes, err := counterparty.QueryClientConsensusState(core.NewQueryContext(ctx, cplatestHeight), restoreHeight)
	if err != nil {
		return err
	}
	var cons ibcexported.ConsensusState
	if err := pr.codec.UnpackAny(counterpartyConsRes.ConsensusState, &cons); err != nil {
		return fmt.Errorf("failed to unpack consensus state: consensus_state=%v %w", counterpartyConsRes.ConsensusState, err)
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

	originClientState, originConsensusState, err := pr.originProver.CreateInitialLightClientState(ctx, clientState.LatestHeight)
	if err != nil {
		return fmt.Errorf("failed to create initial light client state: height=%v %w", clientState.LatestHeight, err)
	}
	originAnyClientState, err := clienttypes.PackClientState(originClientState)
	if err != nil {
		return err
	}
	originAnyConsensusState, err := clienttypes.PackConsensusState(originConsensusState)
	if err != nil {
		return err
	}
	tmpEKI, err := pr.selectNewEnclaveKey(ctx)
	if err != nil {
		return err
	}
	res, err := pr.lcpServiceClient.CreateClient(ctx, &elc.MsgCreateClient{
		ClientId:       elcClientID,
		ClientState:    originAnyClientState,
		ConsensusState: originAnyConsensusState,
		Signer:         tmpEKI.GetEnclaveKeyAddress().Bytes(),
	})
	if err != nil {
		return fmt.Errorf("failed to create ELC client: elc_client_id=%v %w", elcClientID, err)
	}

	// Ensure the restored state is correct

	commitment, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message)
	if err != nil {
		return err
	}
	usm, err := commitment.GetUpdateStateProxyMessage()
	if err != nil {
		return err
	}
	if !usm.PostStateID.EqualBytes(consensusState.StateId) {
		return fmt.Errorf("unexpected state id: expected %v, but got %v", usm.PostStateID, consensusState.StateId)
	}
	if !usm.PostHeight.EQ(restoreHeight) {
		return fmt.Errorf("unexpected height: expected %v, but got %v", restoreHeight, usm.PostHeight)
	}

	pr.getLogger().Info("successfully restored ELC state", "elc_client_id", elcClientID, "state_id", usm.PostStateID.String(), "height", usm.PostHeight)

	return nil
}
