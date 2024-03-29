package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hyperledger-labs/yui-relayer/core"
	oias "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"

	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/datachainlab/lcp-go/sgx/ias"
)

// UpdateEKIIfNeeded checks if the enclave key needs to be updated
func (pr *Prover) UpdateEKIfNeeded(ctx context.Context, verifier core.FinalityAwareChain) error {
	updateNeeded, err := pr.loadEKIAndCheckUpdateNeeded(ctx, verifier)
	if err != nil {
		return err
	}
	log.Printf("loadEKIAndCheckUpdateNeeded: updateNeeded=%v", updateNeeded)
	if !updateNeeded {
		return nil
	}

	// if updateNeeded is true,
	// query new key and register key and set it to memory and save it to file

	pr.activeEnclaveKey, pr.unfinalizedMsgID = nil, nil

	log.Println("need to get a new enclave key")

	eki, err := pr.selectNewEnclaveKey(ctx)
	if err != nil {
		return err
	}
	log.Printf("selected available enclave key: %#v", eki)

	msgID, err := pr.registerEnclaveKey(verifier, eki)
	if err != nil {
		return err
	}
	finalized, success, err := checkMsgStatus(verifier, msgID)
	if err != nil {
		return err
	} else if !success {
		return fmt.Errorf("msg(id=%v) execution failed", msgID)
	}

	if finalized {
		// this path is for chans have instant finality
		// if the msg is finalized, save the enclave key info as finalized
		if err := pr.saveFinalizedEnclaveKeyInfo(ctx, eki); err != nil {
			return err
		}
		pr.activeEnclaveKey = eki
	} else {
		// if the msg is not finalized, save the enclave key info as unfinalized
		if err := pr.saveUnfinalizedEnclaveKeyInfo(ctx, eki, msgID); err != nil {
			return err
		}
		pr.activeEnclaveKey = eki
		pr.unfinalizedMsgID = msgID
	}

	return nil
}

// checkEKIUpdateNeeded checks if the enclave key needs to be updated
// if the enclave key is missing or expired, it returns true
func (pr *Prover) checkEKIUpdateNeeded(ctx context.Context, timestamp time.Time, eki *enclave.EnclaveKeyInfo) bool {
	attestationTime := time.Unix(int64(eki.AttestationTime), 0)

	// TODO consider appropriate buffer time
	updateTime := attestationTime.Add(time.Duration(pr.config.KeyExpiration) * time.Second / 2)
	log.Printf("checkEKIUpdateNeeded: enclave_key=%x now=%v attestation_time=%v expiration=%v update_time=%v", eki.EnclaveKeyAddress, timestamp.Unix(), attestationTime.Unix(), pr.config.KeyExpiration, updateTime.Unix())

	// For now, a half of expiration is used as a buffer time
	if timestamp.After(updateTime) {
		log.Printf("checkEKIUpdateNeeded: enclave key '%x' is expired", eki.EnclaveKeyAddress)
		return true
	}
	// check if the enclave key is still available in the LCP service
	_, err := pr.lcpServiceClient.EnclaveKey(ctx, &enclave.QueryEnclaveKeyRequest{EnclaveKeyAddress: eki.EnclaveKeyAddress})
	if err != nil {
		log.Printf("checkEKIUpdateNeeded: enclave key '%x' not found: error=%v", eki.EnclaveKeyAddress, err)
		return true
	}
	return false
}

// isFinalizedMsg checks if the given msg is finalized in the origin chain
// and returns (finalized, success, error)
// finalized: true if the msg is finalized
// success: true if the msg is successfully executed in the origin chain
// error: non-nil if the msg may not exist in the origin chain
func checkMsgStatus(verifier core.FinalityAwareChain, msgID core.MsgID) (bool, bool, error) {
	lfHeader, err := verifier.GetLatestFinalizedHeader()
	if err != nil {
		return false, false, err
	}
	msgRes, err := verifier.GetMsgResult(msgID)
	if err != nil {
		return false, false, err
	} else if ok, failureReason := msgRes.Status(); !ok {
		log.Printf("msg(%s) execution failed: %v", msgID.String(), failureReason)
		return false, false, nil
	}
	return msgRes.BlockHeight().LTE(lfHeader.GetHeight()), true, nil
}

// if returns true, query new key and register key and set it to memory
func (pr *Prover) loadEKIAndCheckUpdateNeeded(ctx context.Context, verifier core.FinalityAwareChain) (bool, error) {
	now := time.Now()

	// no active enclave key in memory
	if pr.activeEnclaveKey == nil {
		// 1: load the last unfinalized enclave key if exists
		// 2: load the last finalized enclave key if exists
		// 3: select a new enclave key from the LCP service (i.e. return true)

		log.Println("no active enclave key in memory")

		if eki, msgID, err := pr.loadLastUnfinalizedEnclaveKey(ctx); err == nil {
			log.Println("load last unfinalized enclave key into memory")
			pr.activeEnclaveKey = eki
			pr.unfinalizedMsgID = msgID
		} else if errors.Is(err, ErrEnclaveKeyInfoNotFound) {
			log.Println("no unfinalized enclave key info found")
			eki, err := pr.loadLastFinalizedEnclaveKey(ctx)
			if err != nil {
				if errors.Is(err, ErrEnclaveKeyInfoNotFound) {
					log.Println("no enclave key info found")
					return true, nil
				}
				return false, err
			}
			log.Println("load last finalized enclave key into memory")
			pr.activeEnclaveKey = eki
			pr.unfinalizedMsgID = nil
		} else {
			return false, err
		}
	}

	// finalized enclave key
	if pr.unfinalizedMsgID == nil {
		log.Println("active enclave key is finalized")
		// check if the enclave key is still available in the LCP service and not expired
		return pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey), nil
	}

	// unfinalized enclave key

	log.Println("active enclave key is unfinalized")

	if _, err := verifier.GetMsgResult(pr.unfinalizedMsgID); err != nil {
		// err means that the msg is not included in the latest block
		log.Printf("msg(%s) is not included in the latest block: error=%v", pr.unfinalizedMsgID.String(), err)
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	finalized, success, err := checkMsgStatus(verifier, pr.unfinalizedMsgID)
	log.Printf("check unfinalized msg(%s) status: finalized=%v success=%v error=%v", pr.unfinalizedMsgID.String(), finalized, success, err)
	if err != nil {
		return false, err
	} else if !success {
		// tx is failed, so remove the unfinalized enclave key info
		log.Printf("msg(%s) execution failed", pr.unfinalizedMsgID.String())
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		return true, nil
	} else if finalized {
		// tx is successfully executed and finalized
		log.Printf("msg(%s) is finalized", pr.unfinalizedMsgID.String())
		if pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey) {
			return true, nil
		}
		log.Printf("save enclave key info as finalized: enclave key address=%x", pr.activeEnclaveKey.EnclaveKeyAddress)
		if err := pr.saveFinalizedEnclaveKeyInfo(ctx, pr.activeEnclaveKey); err != nil {
			return false, err
		}
		log.Printf("remove old unfinalized enclave key info: enclave key address=%x", pr.activeEnclaveKey.EnclaveKeyAddress)
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		pr.unfinalizedMsgID = nil
		return false, nil
	} else {
		// tx is successfully executed but not finalized yet
		log.Printf("msg(%s) is not finalized yet", pr.unfinalizedMsgID.String())
		return pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey), nil
	}
}

// selectNewEnclaveKey selects a new enclave key from the LCP service
func (pr *Prover) selectNewEnclaveKey(ctx context.Context) (*enclave.EnclaveKeyInfo, error) {
	res, err := pr.lcpServiceClient.AvailableEnclaveKeys(ctx, &enclave.QueryAvailableEnclaveKeysRequest{Mrenclave: pr.config.GetMrenclave()})
	if err != nil {
		return nil, err
	} else if len(res.Keys) == 0 {
		return nil, fmt.Errorf("no available enclave keys")
	}

	for _, eki := range res.Keys {
		if err := ias.VerifyReport(eki.Report, eki.Signature, eki.SigningCert, time.Now()); err != nil {
			return nil, err
		}
		avr, err := ias.ParseAndValidateAVR(eki.Report)
		if err != nil {
			return nil, err
		}
		if pr.checkEKIUpdateNeeded(ctx, time.Now(), eki) {
			log.Printf("key '%x' is not allowed to use because of expiration", eki.EnclaveKeyAddress)
			continue
		}
		if !pr.validateISVEnclaveQuoteStatus(avr.ISVEnclaveQuoteStatus) {
			log.Printf("key '%x' is not allowed to use because of ISVEnclaveQuoteStatus: %v", eki.EnclaveKeyAddress, avr.ISVEnclaveQuoteStatus)
			continue
		}
		if !pr.validateAdvisoryIDs(avr.AdvisoryIDs) {
			log.Printf("key '%x' is not allowed to use because of advisory IDs: %v", eki.EnclaveKeyAddress, avr.AdvisoryIDs)
			continue
		}
		return eki, nil
	}
	return nil, fmt.Errorf("no available enclave keys: all keys are not allowed to use")
}

func (pr *Prover) validateISVEnclaveQuoteStatus(s oias.ISVEnclaveQuoteStatus) bool {
	if s == oias.QuoteOK {
		return true
	}
	for _, status := range pr.config.AllowedQuoteStatuses {
		if s.String() == status {
			return true
		}
	}
	return false
}

func (pr *Prover) validateAdvisoryIDs(ids []string) bool {
	if len(ids) == 0 {
		return true
	}
	allowedSet := mapset.NewSet(pr.config.AllowedAdvisoryIds...)
	targetSet := mapset.NewSet(ids...)
	return targetSet.Difference(allowedSet).Cardinality() == 0
}

func (pr *Prover) syncUpstreamHeader(includeState bool) ([]*elc.MsgUpdateClientResponse, error) {

	// 1. check if the latest height of the client is less than the given height

	res, err := pr.lcpServiceClient.Client(context.TODO(), &elc.QueryClientRequest{ClientId: pr.config.ElcClientId})
	if err != nil {
		return nil, err
	}
	latestHeader, err := pr.originProver.GetLatestFinalizedHeader()
	if err != nil {
		return nil, err
	}

	var clientState ibcexported.ClientState
	if err := pr.codec.UnpackAny(res.ClientState, &clientState); err != nil {
		return nil, err
	}
	if clientState.GetLatestHeight().GTE(latestHeader.GetHeight()) {
		return nil, nil
	}

	log.Printf("syncUpstreamHeader try to update the client in ELC: latest=%v got=%v", clientState.GetLatestHeight(), latestHeader.GetHeight())

	// 2. query the header from the upstream chain

	headers, err := pr.originProver.SetupHeadersForUpdate(NewLCPQuerier(pr.lcpServiceClient, pr.config.ElcClientId), latestHeader)
	if err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, nil
	}

	// 3. send a request that contains a header from 2 to update the client in ELC
	var responses []*elc.MsgUpdateClientResponse
	for _, header := range headers {
		anyHeader, err := clienttypes.PackClientMessage(header)
		if err != nil {
			return nil, err
		}
		res, err := pr.lcpServiceClient.UpdateClient(context.TODO(), &elc.MsgUpdateClient{
			ClientId:     pr.config.ElcClientId,
			Header:       anyHeader,
			IncludeState: includeState,
			Signer:       pr.activeEnclaveKey.EnclaveKeyAddress,
		})
		if err != nil {
			return nil, err
		}
		responses = append(responses, res)
	}

	return responses, nil
}

func (pr *Prover) registerEnclaveKey(verifier core.Chain, eki *enclave.EnclaveKeyInfo) (core.MsgID, error) {
	if err := ias.VerifyReport(eki.Report, eki.Signature, eki.SigningCert, time.Now()); err != nil {
		return nil, err
	}
	if _, err := ias.ParseAndValidateAVR(eki.Report); err != nil {
		return nil, err
	}
	message := &lcptypes.RegisterEnclaveKeyMessage{
		Report:      eki.Report,
		Signature:   eki.Signature,
		SigningCert: eki.SigningCert,
	}
	signer, err := verifier.GetAddress()
	if err != nil {
		return nil, err
	}
	msg, err := clienttypes.NewMsgUpdateClient(pr.path.ClientID, message, signer.String())
	if err != nil {
		return nil, err
	}
	ids, err := verifier.SendMsgs([]sdk.Msg{msg})
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("unexpected number of msgIDs: %v", ids)
	}
	return ids[0], nil
}

func activateClient(pathEnd *core.PathEnd, src, dst *core.ProvableChain) error {
	srcProver := src.Prover.(*Prover)
	if err := srcProver.UpdateEKIfNeeded(context.TODO(), dst); err != nil {
		return err
	}

	// 1. LCP synchronises with the latest header of the upstream chain
	updates, err := srcProver.syncUpstreamHeader(true)
	if err != nil {
		return err
	}

	signer, err := dst.Chain.GetAddress()
	if err != nil {
		return err
	}

	// 2. Create a `MsgUpdateClient`s to apply to the LCP Client with the results of 1.
	var msgs []sdk.Msg
	for _, update := range updates {
		message := &lcptypes.UpdateClientMessage{
			ProxyMessage: update.Message,
			Signer:       update.Signer,
			Signature:    update.Signature,
		}
		if err := message.ValidateBasic(); err != nil {
			return err
		}
		msg, err := clienttypes.NewMsgUpdateClient(pathEnd.ClientID, message, signer.String())
		if err != nil {
			return err
		}
		msgs = append(msgs, msg)
	}

	// 3. Submit the msgs to the LCP Client
	if _, err := dst.SendMsgs(msgs); err != nil {
		return err
	}
	return nil
}

type LCPQuerier struct {
	serviceClient LCPServiceClient
	clientID      string
	core.FinalityAwareChain
}

var _ core.FinalityAwareChain = (*LCPQuerier)(nil)

func NewLCPQuerier(serviceClient LCPServiceClient, clientID string) LCPQuerier {
	return LCPQuerier{
		serviceClient: serviceClient,
		clientID:      clientID,
	}
}

func (q LCPQuerier) ChainID() string {
	return "lcp"
}

// LatestHeight returns the latest height of the chain
func (LCPQuerier) LatestHeight() (ibcexported.Height, error) {
	return clienttypes.ZeroHeight(), nil
}

// Timestamp returns the timestamp corresponding to the height
func (LCPQuerier) Timestamp(ibcexported.Height) (time.Time, error) {
	return time.Time{}, nil
}

// AverageBlockTime returns the average time required for each new block to be committed
func (LCPQuerier) AverageBlockTime() time.Duration {
	return 0
}

// QueryClientState returns the client state of dst chain
// height represents the height of dst chain
func (q LCPQuerier) QueryClientState(ctx core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
	res, err := q.serviceClient.Client(ctx.Context(), &elc.QueryClientRequest{ClientId: q.clientID})
	if err != nil {
		return nil, err
	}
	return &clienttypes.QueryClientStateResponse{
		ClientState: res.ClientState,
	}, nil
}

// QueryClientConsensusState retrevies the latest consensus state for a client in state at a given height
func (q LCPQuerier) QueryClientConsensusState(ctx core.QueryContext, dstClientConsHeight ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {
	// TODO add query_client_consensus support to ecall-handler
	panic("not implemented error")
}
