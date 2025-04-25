package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/avast/retry-go"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger-labs/yui-relayer/core"
	oias "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	opcs "github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"

	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/datachainlab/lcp-go/sgx"
	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/datachainlab/lcp-go/sgx/ias"
)

type RAType uint8

const (
	RATypeIAS             RAType = 1
	RATypeDCAP            RAType = 2
	RATypeZKDCAPRisc0     RAType = 3
	RATypeMockZKDCAPRisc0 RAType = 4
)

type EIP712DomainParams struct {
	ChainId               uint64
	VerifyingContractAddr common.Address
}

// UpdateEKIIfNeeded checks if the enclave key needs to be updated
func (pr *Prover) UpdateEKIIfNeeded(ctx context.Context, counterparty core.FinalityAwareChain) error {
	updateNeeded, err := pr.loadEKIAndCheckUpdateNeeded(ctx, counterparty)
	if err != nil {
		return fmt.Errorf("failed to call loadEKIAndCheckUpdateNeeded: %w", err)
	}
	pr.getLogger().Info("loadEKIAndCheckUpdateNeeded", "updateNeeded", updateNeeded)
	if !updateNeeded {
		return nil
	}

	// if updateNeeded is true,
	// query new key and register key and set it to memory and save it to file

	pr.activeEnclaveKey, pr.unfinalizedMsgID = nil, nil

	pr.getLogger().Info("need to get a new enclave key")

	eki, err := pr.selectNewEnclaveKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to call selectNewEnclaveKey: %w", err)
	}

	pr.getLogger().Info("try to register a new enclave key", "eki", eki)

	msgID, err := pr.registerEnclaveKey(ctx, counterparty, eki)
	if err != nil {
		return fmt.Errorf("failed to call registerEnclaveKey: %w", err)
	}
	pr.getLogger().Info("registered a new enclave key", "enclave_key", eki.GetEnclaveKeyAddress(), "msg_id", msgID.String())
	finalized, success, err := pr.checkMsgStatus(ctx, counterparty, msgID)
	if err != nil {
		return fmt.Errorf("failed to call checkMsgStatus: %w", err)
	} else if !success {
		return fmt.Errorf("msg(id=%v) execution failed", msgID)
	}
	pr.getLogger().Info("check the msg status", "msg_id", msgID.String(), "finalized", finalized, "success", success)

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
func (pr *Prover) checkEKIUpdateNeeded(ctx context.Context, now time.Time, eki *enclave.EnclaveKeyInfo) bool {
	expiredAt := eki.GetExpiredAt(time.Duration(pr.config.KeyExpiration) * time.Second)
	bufferTime := time.Duration(pr.config.KeyUpdateBufferTime) * time.Second
	updateNeededAt := expiredAt.Add(-bufferTime)

	pr.getLogger().Info(
		"checkEKIUpdateNeeded",
		"enclave_key", eki.GetEnclaveKeyAddress().String(),
		"now", now.Unix(),
		"expiration", expiredAt.Unix(),
		"update_needed_at", updateNeededAt.Unix(),
	)

	// If current time is past the updateNeededAt, return true
	if now.After(updateNeededAt) {
		pr.getLogger().Info(
			"checkEKIUpdateNeeded: enclave key needs update",
			"enclave_key", eki.GetEnclaveKeyAddress().String(),
			"expiredAt", expiredAt.Unix(),
			"updateNeededAt", updateNeededAt.Unix(),
			"now", now.Unix(),
		)
		return true
	}

	// check if the enclave key is still available in the LCP service
	_, err := pr.lcpServiceClient.EnclaveKey(ctx, &enclave.QueryEnclaveKeyRequest{EnclaveKeyAddress: eki.GetEnclaveKeyAddress().Bytes()})
	if err != nil {
		pr.getLogger().Warn("checkEKIUpdateNeeded: enclave key not found", "enclave_key", eki.GetEnclaveKeyAddress().String(), "error", err)
		return true
	}
	return false
}

// checkMsgStatus checks if the given msg is finalized in the origin chain
// and returns (finalized, success, error)
// finalized: true if the msg is finalized
// success: true if the msg is successfully executed in the origin chain
// error: non-nil if the msg may not exist in the origin chain
func (pr *Prover) checkMsgStatus(ctx context.Context, counterparty core.FinalityAwareChain, msgID core.MsgID) (bool, bool, error) {
	lfHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return false, false, err
	}
	msgRes, err := counterparty.GetMsgResult(ctx, msgID)
	if err != nil {
		return false, false, err
	} else if ok, failureReason := msgRes.Status(); !ok {
		pr.getLogger().Warn("msg execution failed", "msg_id", msgID.String(), "reason", failureReason)
		return false, false, nil
	}
	return msgRes.BlockHeight().LTE(lfHeader.GetHeight()), true, nil
}

// if returns true, query new key and register key and set it to memory
func (pr *Prover) loadEKIAndCheckUpdateNeeded(ctx context.Context, counterparty core.FinalityAwareChain) (bool, error) {
	now := time.Now()

	// no active enclave key in memory
	if pr.activeEnclaveKey == nil {
		// 1: load the last unfinalized enclave key if exists
		// 2: load the last finalized enclave key if exists
		// 3: select a new enclave key from the LCP service (i.e. return true)

		pr.getLogger().Info("no active enclave key in memory")

		if eki, msgID, err := pr.loadLastUnfinalizedEnclaveKey(ctx); err == nil {
			pr.getLogger().Info("load last unfinalized enclave key into memory")
			pr.activeEnclaveKey = eki
			pr.unfinalizedMsgID = msgID
		} else if errors.Is(err, ErrEnclaveKeyInfoNotFound) {
			pr.getLogger().Info("no unfinalized enclave key info found")
			eki, err := pr.loadLastFinalizedEnclaveKey(ctx)
			if err != nil {
				if errors.Is(err, ErrEnclaveKeyInfoNotFound) {
					pr.getLogger().Info("no enclave key info found")
					return true, nil
				}
				return false, err
			}
			pr.getLogger().Info("load last finalized enclave key into memory")
			pr.activeEnclaveKey = eki
			pr.unfinalizedMsgID = nil
		} else {
			return false, err
		}
	}

	// finalized enclave key
	if pr.unfinalizedMsgID == nil {
		pr.getLogger().Info("active enclave key is finalized")
		// check if the enclave key is still available in the LCP service and not expired
		return pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey), nil
	}

	// unfinalized enclave key

	pr.getLogger().Info("active enclave key is unfinalized")

	if _, err := counterparty.GetMsgResult(ctx, pr.unfinalizedMsgID); err != nil {
		// err means that the msg is not included in the latest block
		pr.getLogger().Info("the msg is not included in the latest block", "msg_id", pr.unfinalizedMsgID.String(), "error", err)
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	finalized, success, err := pr.checkMsgStatus(ctx, counterparty, pr.unfinalizedMsgID)
	pr.getLogger().Info("check the unfinalized msg status", "msg_id", pr.unfinalizedMsgID.String(), "finalized", finalized, "success", success, "error", err)
	if err != nil {
		return false, err
	} else if !success {
		// tx is failed, so remove the unfinalized enclave key info
		pr.getLogger().Warn("the msg execution failed", "msg_id", pr.unfinalizedMsgID.String())
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		return true, nil
	} else if finalized {
		// tx is successfully executed and finalized
		pr.getLogger().Info("the msg is finalized", "msg_id", pr.unfinalizedMsgID.String())
		if pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey) {
			return true, nil
		}
		pr.getLogger().Info("save enclave key info as finalized", "enclave_key", pr.activeEnclaveKey.GetEnclaveKeyAddress().String())
		if err := pr.saveFinalizedEnclaveKeyInfo(ctx, pr.activeEnclaveKey); err != nil {
			return false, err
		}
		pr.getLogger().Info("remove old unfinalized enclave key info", "enclave_key", pr.activeEnclaveKey.GetEnclaveKeyAddress().String())
		if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
			return false, err
		}
		pr.unfinalizedMsgID = nil
		return false, nil
	} else {
		// tx is successfully executed but not finalized yet
		pr.getLogger().Info("the msg is not finalized yet", "msg_id", pr.unfinalizedMsgID.String())
		return pr.checkEKIUpdateNeeded(ctx, now, pr.activeEnclaveKey), nil
	}
}

// selectNewEnclaveKey selects a new enclave key from the LCP service
func (pr *Prover) selectNewEnclaveKey(ctx context.Context) (*enclave.EnclaveKeyInfo, error) {
	req := enclave.QueryAvailableEnclaveKeysRequest{
		Mrenclave:    pr.config.GetMrenclave(),
		EnclaveDebug: pr.config.IsDebugEnclave,
		RaType:       uint32(pr.getRAType()),
	}
	pr.getLogger().Debug("query available enclave keys", "mrenclave", hex.EncodeToString(req.Mrenclave), "debug", req.EnclaveDebug, "ra_type", req.RaType)
	res, err := pr.lcpServiceClient.AvailableEnclaveKeys(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to call AvailableEnclaveKeys: mr_enclave=%v debug=%v ra_type=%v %w", hex.EncodeToString(req.Mrenclave), req.EnclaveDebug, req.RaType, err)
	} else if len(res.Keys) == 0 {
		return nil, fmt.Errorf("no available enclave keys: mrenclave=%v debug=%v ra_type=%v", hex.EncodeToString(req.Mrenclave), req.EnclaveDebug, req.RaType)
	}

	for _, eki := range res.Keys {
		switch v := eki.KeyInfo.(type) {
		case *enclave.EnclaveKeyInfo_Ias:
			if ok, err := pr.validateIASEnclaveKeyInfo(v.Ias); err != nil {
				return nil, fmt.Errorf("failed to validate IAS enclave key info: %w", err)
			} else if !ok {
				continue
			}
		case *enclave.EnclaveKeyInfo_Dcap:
			if ok, err := pr.validateDCAPEnclaveKeyInfo(v.Dcap); err != nil {
				return nil, fmt.Errorf("failed to validate DCAP enclave key info: %w", err)
			} else if !ok {
				continue
			}
		case *enclave.EnclaveKeyInfo_Zkdcap:
			if ok, err := pr.validateZKDCAPEnclaveKeyInfo(v.Zkdcap); err != nil {
				return nil, fmt.Errorf("failed to validate ZKDCAP enclave key info: %w", err)
			} else if !ok {
				continue
			}
		default:
			pr.getLogger().Warn("unexpected eki type", "type", fmt.Sprintf("%T", eki.KeyInfo))
			continue
		}
		if pr.checkEKIUpdateNeeded(ctx, time.Now(), eki) {
			pr.getLogger().Info("the key is not allowed to use because of expiration", "enclave_key", eki.GetEnclaveKeyAddress().String())
			continue
		}
		return eki, nil
	}
	return nil, fmt.Errorf("no available enclave keys: all keys are not allowed to use")
}

func (pr *Prover) validateIASEnclaveKeyInfo(eki *enclave.IASEnclaveKeyInfo) (bool, error) {
	if err := ias.VerifyReport([]byte(eki.Report), eki.Signature, eki.SigningCert, time.Now()); err != nil {
		return false, err
	}
	avr, err := ias.ParseAndValidateAVR([]byte(eki.Report))
	if err != nil {
		return false, err
	}
	if !pr.validateISVEnclaveQuoteStatus(avr.ISVEnclaveQuoteStatus.String()) {
		pr.getLogger().Info("the key is not allowed to use because of ISVEnclaveQuoteStatus", "enclave_key", hex.EncodeToString(eki.EnclaveKeyAddress), "quote_status", avr.ISVEnclaveQuoteStatus.String())
		return false, nil
	}
	if !pr.validateAdvisoryIDs(avr.AdvisoryIDs) {
		pr.getLogger().Info("the key is not allowed to use because of advisory IDs", "enclave_key", hex.EncodeToString(eki.EnclaveKeyAddress), "advisory_ids", avr.AdvisoryIDs)
		return false, nil
	}
	return true, nil
}

func (pr *Prover) validateISVEnclaveQuoteStatus(status string) bool {
	if status == oias.QuoteOK.String() || status == opcs.StatusUpToDate.String() {
		return true
	}
	for _, s := range pr.config.AllowedQuoteStatuses {
		if status == s {
			return true
		}
	}
	return false
}

func (pr *Prover) validateDCAPEnclaveKeyInfo(eki *enclave.DCAPEnclaveKeyInfo) (bool, error) {
	if !pr.validateISVEnclaveQuoteStatus(eki.TcbStatus) {
		pr.getLogger().Info("the key is not allowed to use because of TCB status", "enclave_key", hex.EncodeToString(eki.EnclaveKeyAddress), "tcb_status", eki.TcbStatus)
		return false, nil
	}
	if !pr.validateAdvisoryIDs(eki.AdvisoryIds) {
		pr.getLogger().Info("the key is not allowed to use because of advisory IDs", "enclave_key", hex.EncodeToString(eki.EnclaveKeyAddress), "advisory_ids", eki.AdvisoryIds)
		return false, nil
	}
	return true, nil
}

func (pr *Prover) validateZKDCAPEnclaveKeyInfo(eki *enclave.ZKDCAPEnclaveKeyInfo) (bool, error) {
	if ok, err := pr.validateDCAPEnclaveKeyInfo(eki.Dcap); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}
	zkp := eki.Zkp.GetRisc0()
	if zkp == nil {
		return false, errors.New("currently only RISC0 is supported")
	}
	zkcfg := pr.config.GetRisc0ZkvmConfig()
	if zkcfg == nil {
		return false, errors.New("RISC0 zkvm config is not set")
	}
	expectedImageID := zkcfg.GetImageID()
	if !bytes.Equal(zkp.ImageId, expectedImageID[:]) {
		pr.getLogger().Info("the key is not allowed to use because of RISC0 image ID mismatch", "enclave_key", hex.EncodeToString(eki.Dcap.EnclaveKeyAddress), "image_id", hex.EncodeToString(zkp.ImageId), "expected_image_id", hex.EncodeToString(expectedImageID[:]))
		return false, nil
	}
	return true, nil
}

func (pr *Prover) validateAdvisoryIDs(ids []string) bool {
	if len(ids) == 0 {
		return true
	}
	allowedSet := mapset.NewSet(pr.config.AllowedAdvisoryIds...)
	targetSet := mapset.NewSet(ids...)
	return targetSet.Difference(allowedSet).Cardinality() == 0
}

func (pr *Prover) updateELC(ctx context.Context, elcClientID string, includeState bool) ([]*elc.MsgUpdateClientResponse, error) {

	// 1. check if the latest height of the client is less than the given height

	res, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{ClientId: elcClientID})
	if err != nil {
		return nil, err
	}
	if !res.Found {
		return nil, fmt.Errorf("client not found: client_id=%v", elcClientID)
	}
	latestHeader, err := pr.originProver.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, err
	}

	var clientState ibcexported.ClientState
	if err := pr.codec.UnpackAny(res.ClientState, &clientState); err != nil {
		return nil, err
	}
	if clientState.GetLatestHeight().GTE(latestHeader.GetHeight()) {
		pr.getLogger().Info("no need to update the client", "elc_client_id", elcClientID, "client_state.latest_height", clientState.GetLatestHeight(), "latest", latestHeader.GetHeight())
		return nil, nil
	}

	pr.getLogger().Info("try to setup headers", "elc_client_id", elcClientID, "client_state.latest_height", clientState.GetLatestHeight(), "latest", latestHeader.GetHeight())

	// 2. query the header from the upstream chain

	headers, err := pr.originProver.SetupHeadersForUpdate(ctx, NewLCPQuerier(pr.lcpServiceClient, elcClientID), latestHeader)
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
		res, err := updateClient(ctx, pr.config.GetMaxChunkSizeForUpdateClient(), pr.lcpServiceClient, anyHeader, elcClientID, includeState, pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes())
		if err != nil {
			return nil, err
		}
		responses = append(responses, res)
	}

	return responses, nil
}

func (pr *Prover) registerEnclaveKey(ctx context.Context, counterparty core.FinalityAwareChain, eki *enclave.EnclaveKeyInfo) (core.MsgID, error) {
	switch v := eki.KeyInfo.(type) {
	case *enclave.EnclaveKeyInfo_Ias:
		return pr.registerIASEnclaveKey(ctx, counterparty, v.Ias)
	case *enclave.EnclaveKeyInfo_Zkdcap:
		return pr.registerZKDCAPEnclaveKey(ctx, counterparty, v.Zkdcap)
	case *enclave.EnclaveKeyInfo_Dcap:
		return nil, errors.New("DCAP enclave key is not supported yet")
	default:
		return nil, fmt.Errorf("registerEnclaveKey: unexpected type: %T", eki.KeyInfo)
	}
}

func (pr *Prover) registerIASEnclaveKey(ctx context.Context, counterparty core.Chain, eki *enclave.IASEnclaveKeyInfo) (core.MsgID, error) {
	clientLogger := pr.getClientLogger(pr.originChain.Path().ClientID)
	if err := ias.VerifyReport([]byte(eki.Report), eki.Signature, eki.SigningCert, time.Now()); err != nil {
		return nil, fmt.Errorf("failed to verify AVR signature: %w", err)
	}
	avr, err := ias.ParseAndValidateAVR([]byte(eki.Report))
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate AVR: %w", err)
	}
	quote, err := avr.Quote()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote from AVR: %w", err)
	}
	ek, expectedOperator, err := ias.GetEKAndOperator(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to get EK and operator: %w", err)
	}
	clientLogger.Info("got EK and operator from report data", "ek", ek.String(), "operator", expectedOperator.String())
	message := &lcptypes.RegisterEnclaveKeyMessage{
		Report:            []byte(eki.Report),
		Signature:         eki.Signature,
		SigningCert:       eki.SigningCert,
		OperatorSignature: nil,
	}
	cplatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return nil, err
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, cplatestHeight))
	if err != nil {
		return nil, err
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return nil, fmt.Errorf("failed to unpack client state: client_state=%v %w", counterpartyClientRes.ClientState, err)
	}
	clientState, ok := cs.(*lcptypes.ClientState)
	if !ok {
		return nil, fmt.Errorf("failed to cast client state: %T", cs)
	}
	if !bytes.Equal(clientState.Mrenclave, quote.Report.MRENCLAVE[:]) {
		return nil, fmt.Errorf("MRENCLAVE mismatch: expected 0x%x, but got 0x%x", clientState.Mrenclave, quote.Report.MRENCLAVE[:])
	}
	if pr.IsOperatorEnabled() {
		operator, err := pr.eip712Signer.GetSignerAddress(ctx)
		if err != nil {
			return nil, err
		}
		if operators := clientState.GetOperators(); !slices.Contains(operators, operator) {
			return nil, fmt.Errorf("the operator is not included in the operators: client_state.operators=%v operator=%v", operators, operator)
		}
		if expectedOperator != [20]byte{} && operator != expectedOperator {
			return nil, fmt.Errorf("operator mismatch: expected 0x%x, but got 0x%x", expectedOperator, operator)
		}
		commitment, err := lcptypes.ComputeEIP712RegisterEnclaveKeyHash(eki.Report)
		if err != nil {
			return nil, err
		}
		sig, err := pr.eip712Signer.Sign(ctx, commitment)
		if err != nil {
			return nil, err
		}
		message.OperatorSignature = sig
		clientLogger.Info("operator signature is generated", "operator", operator.String(), "signature", hex.EncodeToString(sig))
	}
	signer, err := counterparty.GetAddress()
	if err != nil {
		return nil, err
	}
	msg, err := clienttypes.NewMsgUpdateClient(counterparty.Path().ClientID, message, signer.String())
	if err != nil {
		return nil, err
	}
	ids, err := counterparty.SendMsgs(ctx, []sdk.Msg{msg})
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("unexpected number of msgIDs: %v", ids)
	}
	return ids[0], nil
}

func (pr *Prover) registerZKDCAPEnclaveKey(ctx context.Context, counterparty core.Chain, eki *enclave.ZKDCAPEnclaveKeyInfo) (core.MsgID, error) {
	clientLogger := pr.getClientLogger(pr.originChain.Path().ClientID)
	zkp := eki.Zkp.GetRisc0()
	if zkp == nil {
		return nil, errors.New("currently only RISC0 is supported")
	}
	output, err := dcap.ParseQuoteVerificationOutput(zkp.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DCAP verifier output: output=%x %w", zkp.Output, err)
	}
	clientLogger.Info("got DCAP verifier output", "output", output)
	message := &lcptypes.ZKDCAPRegisterEnclaveKeyMessage{
		ZkvmType:                uint32(dcap.Risc0ZKVMType),
		QuoteVerificationOutput: zkp.Output,
		Proof:                   zkp.GetProof(),
		OperatorSignature:       nil,
	}
	quote, err := dcap.ParseQuote(eki.Dcap.Quote)
	if err != nil {
		return nil, err
	}
	report, err := dcap.GetSgxReportFromQuote(quote)
	if err != nil {
		return nil, err
	}
	_, expectedOperator, err := sgx.ParseReportData2(report.ReportData())
	if err != nil {
		return nil, err
	}
	cplatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return nil, err
	}
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, cplatestHeight))
	if err != nil {
		return nil, err
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return nil, fmt.Errorf("failed to unpack client state: client_state=%v %w", counterpartyClientRes.ClientState, err)
	}
	clientState, ok := cs.(*lcptypes.ClientState)
	if !ok {
		return nil, fmt.Errorf("failed to cast client state: %T", cs)
	}
	if err := clientState.ValidateRisc0DCAPVerifierOutput(time.Now(), output); err != nil {
		return nil, fmt.Errorf("failed to validate DCAP verifier output: %w", err)
	}
	vis, err := clientState.GetZKDCAPVerifierInfos()
	if err != nil {
		return nil, err
	}
	verifierInfo := vis[0]
	imageID, err := verifierInfo.GetRISC0ImageID()
	if err != nil {
		return nil, fmt.Errorf("failed to get RISC0 image ID: %w", err)
	}
	if !bytes.Equal(imageID[:], zkp.ImageId) {
		return nil, fmt.Errorf("program ID mismatch: expected 0x%x, but got 0x%x", imageID, zkp.ImageId)
	}
	if err := clientState.VerifyRisc0ZKDCAPProof(verifierInfo, output, zkp.GetProof(), pr.config.GetRisc0ZkvmConfig().Mock); err != nil {
		return nil, fmt.Errorf("failed to verify RISC0 ZKDCAP proof: %w", err)
	}
	if pr.IsOperatorEnabled() {
		operator, err := pr.eip712Signer.GetSignerAddress(ctx)
		if err != nil {
			return nil, err
		}
		if operators := clientState.GetOperators(); !slices.Contains(operators, operator) {
			return nil, fmt.Errorf("the operator is not included in the operators: client_state.operators=%v operator=%v", operators, operator)
		}
		if expectedOperator != [20]byte{} && operator != expectedOperator {
			return nil, fmt.Errorf("operator mismatch: expected 0x%x, but got 0x%x", expectedOperator, operator)
		}
		commitment, err := lcptypes.ComputeEIP712ZKDCAPRegisterEnclaveKeyHash(verifierInfo.ToBytes(), crypto.Keccak256Hash(zkp.Output))
		if err != nil {
			return nil, err
		}
		sig, err := pr.eip712Signer.Sign(ctx, commitment)
		if err != nil {
			return nil, err
		}
		message.OperatorSignature = sig
		clientLogger.Info("operator signature is generated", "operator", operator.String(), "signature", hex.EncodeToString(sig))
	}
	signer, err := counterparty.GetAddress()
	if err != nil {
		return nil, err
	}
	msg, err := clienttypes.NewMsgUpdateClient(counterparty.Path().ClientID, message, signer.String())
	if err != nil {
		return nil, err
	}
	ids, err := counterparty.SendMsgs(ctx, []sdk.Msg{msg})
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("unexpected number of msgIDs: %v", ids)
	}
	return ids[0], nil
}

func (pr *Prover) ComputeEIP712UpdateOperatorsHash(nonce uint64, newOperators []common.Address, thresholdNumerator, thresholdDenominator uint64) (common.Hash, error) {
	params := pr.getDomainParams()
	bz, err := lcptypes.ComputeEIP712UpdateOperators(int64(params.ChainId), params.VerifyingContractAddr, pr.computeEIP712ChainSalt(), pr.counterpartyPath.ClientID, nonce, newOperators, thresholdNumerator, thresholdDenominator)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(bz), nil
}

func (pr *Prover) getDomainParams() EIP712DomainParams {
	switch pr.config.ChainType() {
	case lcptypes.ChainTypeEVM:
		params := pr.config.GetOperatorsEip712EvmChainParams()
		return EIP712DomainParams{
			ChainId:               params.ChainId,
			VerifyingContractAddr: common.HexToAddress(params.VerifyingContractAddress),
		}
	case lcptypes.ChainTypeCosmos:
		return EIP712DomainParams{
			ChainId:               0,
			VerifyingContractAddr: common.Address{},
		}
	default:
		panic(fmt.Sprintf("unsupported chain type: %v", pr.config.ChainType()))
	}
}

func (pr *Prover) computeEIP712ChainSalt() common.Hash {
	switch pr.config.ChainType() {
	case lcptypes.ChainTypeEVM:
		return pr.computeEIP712EVMChainSalt()
	case lcptypes.ChainTypeCosmos:
		return pr.computeEIP712CosmosChainSalt()
	default:
		panic(fmt.Sprintf("unsupported chain type: %v", pr.config.ChainType()))
	}
}

func (pr *Prover) computeEIP712EVMChainSalt() common.Hash {
	var bz [2]byte
	binary.BigEndian.PutUint16(bz[:], lcptypes.ChainTypeEVM.Uint16())
	return crypto.Keccak256Hash(bz[:])
}

func (pr *Prover) computeEIP712CosmosChainSalt() common.Hash {
	params := pr.config.GetOperatorsEip712CosmosChainParams()
	return lcptypes.ComputeCosmosChainSalt(params.ChainId, []byte(params.Prefix))
}

type AvailableEnclaveKeysResult struct {
	Keys          []*enclave.EnclaveKeyInfo `json:"keys"`
	keyExpiration time.Duration             `json:"-"`
}

func (res *AvailableEnclaveKeysResult) MarshalJSON() ([]byte, error) {
	type enclaveKeyInfo struct {
		EnclaveKeyAddress string                  `json:"enclave_key_address,omitempty"`
		ExpiredAt         uint64                  `json:"update_time,omitempty"`
		KeyInfo           *enclave.EnclaveKeyInfo `json:"key_info,omitempty"`
	}
	type availableEnclaveKeysResult struct {
		Keys []*enclaveKeyInfo `json:"keys"`
	}
	var keys []*enclaveKeyInfo
	for _, key := range res.Keys {
		keys = append(keys, &enclaveKeyInfo{
			EnclaveKeyAddress: key.GetEnclaveKeyAddress().String(),
			ExpiredAt:         uint64(key.GetExpiredAt(res.keyExpiration).Unix()),
			KeyInfo:           key,
		})
	}
	return json.Marshal(&availableEnclaveKeysResult{Keys: keys})
}

func bytes2Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(b)
}

func (pr *Prover) doAvailableEnclaveKeys(ctx context.Context) (*AvailableEnclaveKeysResult, error) {
	res, err := pr.lcpServiceClient.AvailableEnclaveKeys(ctx, &enclave.QueryAvailableEnclaveKeysRequest{Mrenclave: pr.config.GetMrenclave()})
	if err != nil {
		return nil, err
	}
	return &AvailableEnclaveKeysResult{Keys: res.Keys, keyExpiration: time.Duration(pr.config.KeyExpiration) * time.Second}, nil
}

type CreateELCResult struct {
	Created bool                              `json:"created"`
	Message *lcptypes.UpdateStateProxyMessage `json:"message,omitempty"`
}

// height: 0 means the latest height
func (pr *Prover) doCreateELC(ctx context.Context, elcClientID string, height uint64) (*CreateELCResult, error) {
	header, err := pr.originProver.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, err
	}
	latestHeight := header.GetHeight()
	if height == 0 {
		height = latestHeight.GetRevisionHeight()
	} else if height >= latestHeight.GetRevisionHeight() {
		return nil, fmt.Errorf("height %v is greater than the latest height %v", height, latestHeight.GetRevisionHeight())
	}
	h := clienttypes.NewHeight(latestHeight.GetRevisionNumber(), height)
	pr.getLogger().Info("try to create ELC client", "elc_client_id", elcClientID, "height", h)
	res, err := pr.createELC(ctx, elcClientID, h)
	if err != nil {
		return nil, err
	} else if res == nil {
		pr.getLogger().Info("no need to create ELC client", "elc_client_id", elcClientID)
		return &CreateELCResult{Created: false}, nil
	}
	pr.getLogger().Info("created ELC client", "elc_client_id", elcClientID, "height", h)
	// ensure the message is valid
	msg, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message)
	if err != nil {
		return nil, err
	}
	m, err := msg.GetUpdateStateProxyMessage()
	if err != nil {
		return nil, err
	}
	pr.getLogger().Info("created state", "post_height", m.PostHeight, "post_state_id", m.PostStateID.String(), "timestamp", m.Timestamp.String())
	return &CreateELCResult{
		Created: true,
		Message: m,
	}, nil
}

type UpdateELCResult struct {
	Messages []*lcptypes.UpdateStateProxyMessage `json:"messages"`
}

func (pr *Prover) doUpdateELC(ctx context.Context, elcClientID string) (*UpdateELCResult, error) {
	if pr.activeEnclaveKey == nil {
		eki, err := pr.selectNewEnclaveKey(ctx)
		if err != nil {
			return nil, err
		}
		pr.getLogger().Info("use a new enclave key", "enclave_key", eki.GetEnclaveKeyAddress().String())
		pr.activeEnclaveKey = eki
	}
	pr.getLogger().Info("try to update the ELC client", "elc_client_id", elcClientID)
	updates, err := pr.updateELC(ctx, elcClientID, false)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		pr.getLogger().Info("no update is needed")
		return &UpdateELCResult{
			Messages: []*lcptypes.UpdateStateProxyMessage{},
		}, nil
	}
	var msgs []*lcptypes.UpdateStateProxyMessage
	for i, update := range updates {
		commitment, err := lcptypes.EthABIDecodeHeaderedProxyMessage(update.Message)
		if err != nil {
			return nil, fmt.Errorf("failed EthABIDecodeHeaderedProxyMessage: index=%v %w", i, err)
		}
		msg, err := commitment.GetUpdateStateProxyMessage()
		if err != nil {
			return nil, fmt.Errorf("failed GetUpdateStateProxyMessage: index=%v %w", i, err)
		}
		pr.getLogger().Info("updated state", "prev_height", msg.PrevHeight, "prev_state_id", msg.PrevStateID.String(), "post_height", msg.PostHeight, "post_state_id", msg.PostStateID.String(), "timestamp", msg.Timestamp.String())
		msgs = append(msgs, msg)
	}
	return &UpdateELCResult{
		Messages: msgs,
	}, nil
}

type QueryELCResult struct {
	// if false, `Raw` and `Decoded` are empty
	Found bool `json:"found"`
	Raw   struct {
		ClientState    Any `json:"client_state"`
		ConsensusState Any `json:"consensus_state"`
	} `json:"raw"`
	// if cannot decode the client state or the consensus state, `Decoded` is empty
	Decoded struct {
		ClientState    ibcexported.ClientState    `json:"client_state"`
		ConsensusState ibcexported.ConsensusState `json:"consensus_state"`
	} `json:"decoded,omitempty"`
}

type Any struct {
	TypeURL string `json:"type_url"`
	Value   []byte `json:"value"`
}

func (pr *Prover) doQueryELC(ctx context.Context, elcClientID string) (*QueryELCResult, error) {
	r, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{ClientId: elcClientID})
	if err != nil {
		return nil, err
	} else if !r.Found {
		return &QueryELCResult{
			Found: false,
		}, nil
	}
	var result QueryELCResult
	result.Found = true
	result.Raw.ClientState = Any{
		TypeURL: r.ClientState.TypeUrl,
		Value:   r.ClientState.Value,
	}
	result.Raw.ConsensusState = Any{
		TypeURL: r.ConsensusState.TypeUrl,
		Value:   r.ConsensusState.Value,
	}
	var (
		clientState    ibcexported.ClientState
		consensusState ibcexported.ConsensusState
	)
	if err := pr.codec.UnpackAny(r.ClientState, &clientState); err != nil {
		pr.getLogger().Warn("failed to unpack client state", "error", err)
		return &result, nil
	}
	if err := pr.codec.UnpackAny(r.ConsensusState, &consensusState); err != nil {
		pr.getLogger().Warn("failed to unpack consensus state", "error", err)
		return &result, nil
	}
	result.Decoded.ClientState = clientState
	result.Decoded.ConsensusState = consensusState
	return &result, nil
}

func (pr *Prover) createELC(ctx context.Context, elcClientID string, height ibcexported.Height) (*elc.MsgCreateClientResponse, error) {
	res, err := pr.lcpServiceClient.Client(ctx, &elc.QueryClientRequest{ClientId: elcClientID})
	if err != nil {
		return nil, err
	} else if res.Found {
		return nil, nil
	}
	// NOTE: Query the LCP for available keys, but no need to register it into on-chain here
	tmpEKI, err := pr.selectNewEnclaveKey(ctx)
	if err != nil {
		return nil, err
	}
	originClientState, originConsensusState, err := pr.originProver.CreateInitialLightClientState(ctx, height)
	if err != nil {
		return nil, err
	}
	anyOriginClientState, err := clienttypes.PackClientState(originClientState)
	if err != nil {
		return nil, err
	}
	anyOriginConsensusState, err := clienttypes.PackConsensusState(originConsensusState)
	if err != nil {
		return nil, err
	}
	return pr.lcpServiceClient.CreateClient(ctx, &elc.MsgCreateClient{
		ClientId:       elcClientID,
		ClientState:    anyOriginClientState,
		ConsensusState: anyOriginConsensusState,
		Signer:         tmpEKI.GetEnclaveKeyAddress().Bytes(),
	})
}

func activateClient(ctx context.Context, pathEnd *core.PathEnd, src, dst *core.ProvableChain, retryInterval time.Duration, retryMaxAttempts uint) error {
	srcProver := src.Prover.(*Prover)
	if err := srcProver.UpdateEKIIfNeeded(ctx, dst); err != nil {
		return err
	}

	srcProver.getLogger().Info("try to activate the LCP client", "elc_client_id", srcProver.config.ElcClientId)

	// 1. LCP client synchronises with the latest header of the upstream chain
	var updates []*elc.MsgUpdateClientResponse
	if err := retry.Do(func() error {
		var err error
		updates, err = srcProver.updateELC(ctx, srcProver.config.ElcClientId, true)
		if err != nil {
			return err
		} else if len(updates) == 0 {
			return fmt.Errorf("no available updates: elc_client_id=%v", srcProver.config.ElcClientId)
		}
		return nil
	}, retry.Attempts(retryMaxAttempts+1), retry.Delay(retryInterval), retry.Context(ctx)); err != nil {
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
			Signatures:   [][]byte{update.Signature},
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
	if _, err := dst.SendMsgs(ctx, msgs); err != nil {
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
func (LCPQuerier) LatestHeight(_ context.Context) (ibcexported.Height, error) {
	return clienttypes.ZeroHeight(), nil
}

// Timestamp returns the timestamp corresponding to the height
func (LCPQuerier) Timestamp(_ context.Context, _ ibcexported.Height) (time.Time, error) {
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
