package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/go-risc0-verifier/groth16"
	"github.com/datachainlab/go-risc0-verifier/mock"
	"github.com/datachainlab/lcp-go/sgx"
	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/datachainlab/lcp-go/sgx/ias"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type EKInfo struct {
	ExpiredAt uint64
	Operator  common.Address
}

func (ei EKInfo) IsExpired(blockTime time.Time) bool {
	return time.Unix(int64(ei.ExpiredAt), 0).Before(blockTime)
}

func (ei EKInfo) IsMatchOperator(operator common.Address) bool {
	return ei.Operator == operator
}

func (cs ClientState) VerifyClientMessage(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, clientMsg exported.ClientMessage) error {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err)
		}
		if err := cs.VerifySignatures(ctx, clientStore, crypto.Keccak256Hash(clientMsg.ProxyMessage), clientMsg.Signatures); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, err.Error())
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.verifyUpdateClient(ctx, cdc, clientStore, clientMsg, pmsg)
		case *MisbehaviourProxyMessage:
			return cs.verifyMisbehaviour(ctx, cdc, clientStore, clientMsg, pmsg)
		default:
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg)
		}
	case *RegisterEnclaveKeyMessage:
		return cs.verifyRegisterEnclaveKey(ctx, clientStore, clientMsg)
	case *ZKDCAPRegisterEnclaveKeyMessage:
		return cs.verifyZKDCAPRegisterEnclaveKey(ctx, clientStore, clientMsg)
	case *UpdateOperatorsMessage:
		return cs.verifyUpdateOperators(ctx, clientStore, clientMsg)
	default:
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg)
	}
}

func (cs ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg exported.ClientMessage) {
	cs.Frozen = true
	clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, &cs))
}

func (cs ClientState) verifyUpdateClient(ctx sdk.Context, cdc codec.BinaryCodec, store storetypes.KVStore, msg *UpdateClientMessage, pmsg *UpdateStateProxyMessage) error {
	if cs.LatestHeight.IsZero() {
		if len(pmsg.EmittedStates) == 0 {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `NewState` must be non-nil", msg)
		}
	} else {
		if pmsg.PrevHeight == nil || pmsg.PrevStateID == nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message %v: `PrevHeight` and `PrevStateID` must be non-nil", msg)
		}
		prevConsensusState, err := GetConsensusState(store, cdc, pmsg.PrevHeight)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get consensus state: %v", err)
		}
		if !bytes.Equal(prevConsensusState.StateId, pmsg.PrevStateID[:]) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected StateID: expected=%v actual=%v", prevConsensusState.StateId, pmsg.PrevStateID[:])
		}
	}

	if err := pmsg.Context.Validate(ctx.BlockTime()); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid context: %v", err)
	}

	return nil
}

func (cs ClientState) verifyRegisterEnclaveKey(ctx sdk.Context, store storetypes.KVStore, message *RegisterEnclaveKeyMessage) error {
	// TODO define error types

	if err := ias.VerifyReport(message.Report, message.Signature, message.SigningCert, ctx.BlockTime()); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: message=%v, err=%v", message, err)
	}
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err)
	}
	quoteStatus := avr.ISVEnclaveQuoteStatus.String()
	if quoteStatus == ias.QuoteOK {
		if len(avr.AdvisoryIDs) != 0 {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "advisory IDs should be empty when status is OK: actual=%v", avr.AdvisoryIDs)
		}
	} else {
		if !cs.isAllowedStatus(quoteStatus) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed quote status exists: allowed=%v actual=%v", cs.AllowedQuoteStatuses, quoteStatus)
		}
		if !cs.isAllowedAdvisoryIDs(avr.AdvisoryIDs) {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed advisory ID(s) exists: allowed=%v actual=%v", cs.AllowedAdvisoryIds, avr.AdvisoryIDs)
		}
	}
	quote, err := avr.Quote()
	if err != nil {
		return err
	}
	if !bytes.Equal(cs.Mrenclave, quote.Report.MRENCLAVE[:]) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: mrenclave mismatch: expected=%v actual=%v", cs.Mrenclave, quote.Report.MRENCLAVE[:])
	}
	var operator common.Address
	if len(message.OperatorSignature) > 0 {
		commitment, err := ComputeEIP712RegisterEnclaveKeyHash(string(message.Report))
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute commitment: %v", err)
		}
		operator, err = RecoverAddress(commitment, message.OperatorSignature)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: %v", err)
		}
	}
	ek, expectedOperator, err := ias.GetEKAndOperator(quote)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get enclave key and operator: %v", err)
	}
	if (expectedOperator != common.Address{}) && operator != expectedOperator {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid operator: expected=%v actual=%v", expectedOperator, operator)
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if cs.Contains(store, ek) {
		if err := cs.ensureEKInfoMatch(store, ek, operator, expiredAt); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid enclave key info: %v", err)
		}
	}
	return nil
}

func (cs ClientState) verifyZKDCAPRegisterEnclaveKey(ctx sdk.Context, store storetypes.KVStore, message *ZKDCAPRegisterEnclaveKeyMessage) error {
	if !cs.IsZKDCAPEnabled() {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "zkDCAP is not enabled")
	}
	vis, err := cs.GetZKDCAPVerifierInfos()
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get zkDCAP verifier info: %v", err)
	}
	vi := vis[0]
	if message.ZkvmType != uint32(vi.ZKVMType) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unsupported ZKVM type: expected=%v actual=%v", vi.ZKVMType, message.ZkvmType)
	}
	commit, err := dcap.ParseDCAPVerifierCommit(message.Commit)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to parse DCAP verifier commit: %v", err)
	}
	_, _, err = sgx.ParseReportData2(commit.ReportData())
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to parse report data: %v", err)
	}
	mrenclave := commit.GetEnclaveIdentity().MrEnclave
	if !bytes.Equal(cs.Mrenclave, mrenclave[:]) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid DCAP verifier commit: mrenclave mismatch: expected=%v actual=%v", cs.Mrenclave, mrenclave)
	}
	if debug, err := commit.IsDebug(); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to check debug: %v", err)
	} else if debug != dcap.GetAllowDebugEnclaves() {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid DCAP verifier commit: unexpected debug flag: expected=%v actual=%v", dcap.GetAllowDebugEnclaves(), debug)
	}
	if err := cs.ValidateRisc0DCAPVerifierCommit(ctx.BlockTime(), commit); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid DCAP verifier commit: %v", err)
	}
	if err := cs.VerifyRisc0ZKDCAPProof(vi, commit, message.Proof, risc0MockProofAllowed()); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to verify ZKP: %v", err)
	}
	var operator common.Address
	if len(message.OperatorSignature) > 0 {
		commitment, err := ComputeEIP712ZKDCAPRegisterEnclaveKeyHash(vi.ToBytes(), crypto.Keccak256Hash(message.Commit))
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute commitment: %v", err)
		}
		operator, err = RecoverAddress(commitment, message.OperatorSignature)
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: %v", err)
		}
	}
	ek, expectedOperator, err := sgx.ParseReportData2(commit.ReportData())
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to parse report data: %v", err)
	}
	if (expectedOperator != common.Address{}) && operator != expectedOperator {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid operator: expected=%v actual=%v", expectedOperator, operator)
	}
	if cs.Contains(store, ek) {
		if err := cs.ensureEKInfoMatch(store, ek, operator, commit.GetExpiredAt()); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid enclave key info: %v", err)
		}
	}
	return nil
}

func (cs ClientState) VerifyRisc0ZKDCAPProof(verifierInfo *dcap.ZKDCAPVerifierInfo, commit *dcap.VerifiedOutput, proof []byte, mockProofAllowed bool) error {
	if verifierInfo.ZKVMType != dcap.Risc0ZKVMType {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unsupported ZKVM type: expected=%v actual=%v", dcap.Risc0ZKVMType, verifierInfo.ZKVMType)
	}
	if len(proof) < 4 {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid proof length: expected>=4 actual=%v", len(proof))
	}
	var sel [4]byte
	copy(sel[:], proof[:4])
	if !bytes.Equal(sel[:], mock.MockSelector[:]) {
		if err := groth16.VerifyRISC0SealBySelector(sel, proof[4:], verifierInfo.ProgramID, commit.Digest()); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to verify RISC0 proof: %v", err)
		}
	} else if mockProofAllowed {
		if err := mock.VerifyMockSealBySelector(sel, proof[4:], verifierInfo.ProgramID, commit.Digest()); err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to verify RISC0 mock proof: %v", err)
		}
	} else {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "mock proof is not allowed")
	}
	return nil
}

func (cs ClientState) ValidateRisc0DCAPVerifierCommit(blockTimestamp time.Time, commit *dcap.VerifiedOutput) error {
	if commit.QuoteVersion != dcap.QEVersion3 {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unsupported quote version: expected=%v actual=%v", dcap.QEVersion3, commit.QuoteVersion)
	}
	if commit.TeeType != dcap.TEETypeSGX {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unsupported TEE type: expected=%v actual=%v", dcap.TEETypeSGX, commit.TeeType)
	}
	mrenclave := commit.GetEnclaveIdentity().MrEnclave
	if !bytes.Equal(cs.Mrenclave, mrenclave[:]) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid DCAP verifier commit: mrenclave mismatch: expected=%v actual=%v", cs.Mrenclave, mrenclave)
	}
	if !cs.isAllowedStatus(commit.TcbStatus.String()) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed TCB status: allowed=%v actual=%v", cs.AllowedQuoteStatuses, commit.TcbStatus)
	}
	if !cs.isAllowedAdvisoryIDs(commit.AdvisoryIds) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "disallowed advisory ID(s) exists: allowed=%v actual=%v", cs.AllowedAdvisoryIds, commit.AdvisoryIds)
	}
	if commit.SGXIntelRootCAHash != dcap.HashTrustRootCert() {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid DCAP verifier commit: SGXIntelRootCAHash mismatch: expected=%x actual=%x", dcap.HashTrustRootCert(), commit.SGXIntelRootCAHash)
	}
	if !commit.Validity.ValidateTime(blockTimestamp) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid current time: expected=%v-%v actual=%v", commit.Validity.NotBeforeMax, commit.Validity.NotAfterMin, blockTimestamp.Unix())
	}
	return nil
}

func (cs ClientState) verifyUpdateOperators(ctx sdk.Context, store storetypes.KVStore, message *UpdateOperatorsMessage) error {
	if err := message.ValidateBasic(); err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err)
	}
	if len(cs.Operators) == 0 {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "permissionless operators")
	}
	clientID, err := getClientID(store)
	if err != nil {
		return err
	}
	nextNonce := cs.OperatorsNonce + 1
	if message.Nonce != nextNonce {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid nonce: expected=%v actual=%v clientID=%v", nextNonce, message.Nonce, clientID)
	}
	newOperators, err := message.GetNewOperators()
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get new operators: %v clientID=%v", err, clientID)
	}
	var zeroAddr common.Address
	for i, op := range newOperators {
		if op == zeroAddr {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid operator: operator address must not be zero: clientID=%v", clientID)
		}
		// check if the operators are ordered
		if i > 0 && bytes.Compare(newOperators[i-1].Bytes(), op.Bytes()) > 0 {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "operator addresses must be ordered: clientID=%v op0=%v op1=%v", clientID, newOperators[i-1].String(), op.String())
		}
	}
	signBytes, err := ComputeEIP712CosmosUpdateOperators(
		ctx.ChainID(),
		[]byte(exported.StoreKey),
		clientID,
		message.Nonce,
		newOperators,
		message.NewOperatorsThresholdNumerator,
		message.NewOperatorsThresholdDenominator,
	)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute sign bytes: err=%v clientID=%v", err, clientID)
	}
	commitment := crypto.Keccak256Hash(signBytes)
	var success uint64 = 0
	for i, op := range cs.GetOperators() {
		if len(message.Signatures[i]) == 0 {
			continue
		}
		addr, err := RecoverAddress(commitment, message.Signatures[i])
		if err != nil {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: err=%v clientID=%v", err, clientID)
		}
		if addr != op {
			return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid operator: expected=%v actual=%v clientID=%v", op, addr, clientID)
		}
		success++
	}
	if success*cs.OperatorsThresholdDenominator < cs.OperatorsThresholdDenominator*uint64(len(cs.Operators)) {
		return errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "insufficient signatures: expected=%v actual=%v clientID=%v", cs.OperatorsThresholdDenominator, success, clientID)
	}
	return nil
}

func (cs ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	switch clientMsg := clientMsg.(type) {
	case *UpdateClientMessage:
		pmsg, err := clientMsg.GetProxyMessage()
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid message: %v", err))
		}
		switch pmsg := pmsg.(type) {
		case *UpdateStateProxyMessage:
			return cs.updateClient(cdc, clientStore, pmsg)
		default:
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unexpected message type: %T", pmsg))
		}
	case *RegisterEnclaveKeyMessage:
		return cs.registerEnclaveKey(ctx, clientStore, clientMsg)
	case *ZKDCAPRegisterEnclaveKeyMessage:
		return cs.registerZKDCAPEnclaveKey(ctx, clientStore, clientMsg)
	case *UpdateOperatorsMessage:
		return cs.updateOperators(ctx, cdc, clientStore, clientMsg)
	default:
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "unknown client message %T", clientMsg))
	}
}

func (cs ClientState) updateClient(cdc codec.BinaryCodec, clientStore storetypes.KVStore, msg *UpdateStateProxyMessage) []exported.Height {
	if cs.LatestHeight.LT(msg.PostHeight) {
		cs.LatestHeight = msg.PostHeight
	}
	consensusState := ConsensusState{StateId: msg.PostStateID[:], Timestamp: msg.Timestamp.Uint64()}

	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, &consensusState, msg.PostHeight)
	return nil
}

func (cs ClientState) registerEnclaveKey(ctx sdk.Context, clientStore storetypes.KVStore, message *RegisterEnclaveKeyMessage) []exported.Height {
	avr, err := ias.ParseAndValidateAVR(message.Report)
	if err != nil {
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "invalid AVR: report=%v err=%v", message.Report, err))
	}
	quote, err := avr.Quote()
	if err != nil {
		panic(err)
	}
	ek, _, err := ias.GetEKAndOperator(quote)
	if err != nil {
		panic(err)
	}
	var operator common.Address
	if len(message.OperatorSignature) > 0 {
		commitment, err := ComputeEIP712RegisterEnclaveKeyHash(string(message.Report))
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute commitment: %v", err))
		}
		operator, err = RecoverAddress(commitment, message.OperatorSignature)
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: %v", err))
		}
	}
	expiredAt := avr.GetTimestamp().Add(cs.getKeyExpiration())
	if cs.Contains(clientStore, ek) {
		if err := cs.ensureEKInfoMatch(clientStore, ek, operator, expiredAt); err != nil {
			panic(err)
		}
		return nil
	} else {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				EventTypeRegisterEnclaveKey,
				sdk.NewAttribute(AttributeKeyEnclaveKey, ek.Hex()),
				sdk.NewAttribute(AttributeKeyExpiredAt, expiredAt.String()),
				sdk.NewAttribute(AttributeKeyOperator, operator.Hex()),
			),
		)
	}
	if err := cs.SetEKInfo(clientStore, ek, operator, expiredAt); err != nil {
		panic(err)
	}
	return nil
}

func (cs ClientState) registerZKDCAPEnclaveKey(ctx sdk.Context, clientStore storetypes.KVStore, message *ZKDCAPRegisterEnclaveKeyMessage) []exported.Height {
	commit, err := dcap.ParseDCAPVerifierCommit(message.Commit)
	if err != nil {
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to parse DCAP verifier commit: %v", err))
	}
	ek, _, err := sgx.ParseReportData2(commit.ReportData())
	if err != nil {
		panic(err)
	}
	vis, err := cs.GetZKDCAPVerifierInfos()
	if err != nil {
		panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to get zkDCAP verifier info: %v", err))
	}
	var operator common.Address
	if len(message.OperatorSignature) > 0 {
		commitment, err := ComputeEIP712ZKDCAPRegisterEnclaveKeyHash(vis[0].ToBytes(), crypto.Keccak256Hash(message.Commit))
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to compute commitment: %v", err))
		}
		operator, err = RecoverAddress(commitment, message.OperatorSignature)
		if err != nil {
			panic(errorsmod.Wrapf(clienttypes.ErrInvalidHeader, "failed to recover operator address: %v", err))
		}
	}
	expiredAt := commit.GetExpiredAt()
	if cs.Contains(clientStore, ek) {
		if err := cs.ensureEKInfoMatch(clientStore, ek, operator, expiredAt); err != nil {
			panic(err)
		}
		return nil
	} else {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				EventTypeZKDCAPRegisterEnclaveKey,
				sdk.NewAttribute(AttributeKeyEnclaveKey, ek.Hex()),
				sdk.NewAttribute(AttributeKeyExpiredAt, expiredAt.String()),
				sdk.NewAttribute(AttributeKeyOperator, operator.Hex()),
			),
		)
	}
	if err := cs.SetEKInfo(clientStore, ek, operator, expiredAt); err != nil {
		panic(err)
	}
	return nil
}

func (cs ClientState) updateOperators(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, message *UpdateOperatorsMessage) []exported.Height {
	cs.Operators = message.NewOperators
	cs.OperatorsThresholdNumerator = message.NewOperatorsThresholdNumerator
	cs.OperatorsThresholdDenominator = message.NewOperatorsThresholdDenominator
	cs.OperatorsNonce = message.Nonce
	setClientState(clientStore, cdc, &cs)

	newOperators, err := message.GetNewOperators()
	if err != nil {
		panic(err)
	}
	newOperatorsJSON, err := json.Marshal(newOperators)
	if err != nil {
		panic(err)
	}
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			EventTypeUpdateOperators,
			sdk.NewAttribute(AttributeKeyNonce, fmt.Sprint(message.Nonce)),
			sdk.NewAttribute(AttributeKeyNewOperators, string(newOperatorsJSON)),
			sdk.NewAttribute(AttributeKeyThresholdNumerator, fmt.Sprint(message.NewOperatorsThresholdNumerator)),
			sdk.NewAttribute(AttributeKeyThresholdDenominator, fmt.Sprint(message.NewOperatorsThresholdDenominator)),
		),
	)
	return nil
}

func (cs ClientState) Contains(clientStore storetypes.KVStore, ek common.Address) bool {
	return clientStore.Has(enclaveKeyPath(ek))
}

func (cs ClientState) GetEKInfo(clientStore storetypes.KVStore, ek common.Address) (*EKInfo, error) {
	if !cs.Contains(clientStore, ek) {
		return nil, nil
	}
	bz := clientStore.Get(enclaveKeyPath(ek))
	if len(bz) != (8 + 20) {
		return nil, fmt.Errorf("invalid enclave key info: expected=%v actual=%v", 8+20, len(bz))
	}
	return &EKInfo{
		ExpiredAt: sdk.BigEndianToUint64(bz[:8]),
		Operator:  common.BytesToAddress(bz[8:]),
	}, nil
}

func (cs ClientState) ensureEKInfoMatch(clientStore storetypes.KVStore, ek common.Address, operator common.Address, expiredAt time.Time) error {
	ekInfo, err := cs.GetEKInfo(clientStore, ek)
	if err != nil {
		return err
	}
	if ekInfo == nil {
		return fmt.Errorf("enclave key '%v' not found", ek)
	}
	if ekInfo.Operator != operator {
		return fmt.Errorf("enclave key '%v' operator mismatch: expected=%v actual=%v", ek, operator, ekInfo.Operator)
	}
	if ekInfo.ExpiredAt != uint64(expiredAt.Unix()) {
		return fmt.Errorf("enclave key '%v' expiredAt mismatch: expected=%v actual=%v", ek, expiredAt, time.Unix(int64(ekInfo.ExpiredAt), 0))
	}
	return nil
}

func (cs ClientState) SetEKInfo(clientStore storetypes.KVStore, ek, operator common.Address, expiredAt time.Time) error {
	clientStore.Set(enclaveKeyPath(ek), append(sdk.Uint64ToBigEndian(uint64(expiredAt.Unix())), operator.Bytes()...))
	return nil
}

func (cs ClientState) VerifySignatures(ctx sdk.Context, clientStore storetypes.KVStore, commitment [32]byte, signatures [][]byte) error {
	operators := cs.GetOperators()
	sigNum := len(signatures)
	opNum := len(operators)
	if opNum == 0 {
		if sigNum != 1 {
			return fmt.Errorf("invalid signature length: expected=%v actual=%v", 1, sigNum)
		}
		ek, err := RecoverAddress(commitment, signatures[0])
		if err != nil {
			return err
		}
		ekInfo, err := cs.GetEKInfo(clientStore, ek)
		if err != nil {
			return err
		} else if ekInfo == nil {
			return fmt.Errorf("enclave key '%v' not found", ek)
		} else if ekInfo.IsExpired(ctx.BlockTime()) {
			return fmt.Errorf("enclave key '%v' is expired: expired_at=%v block_time=%v", ek, time.Unix(int64(ekInfo.ExpiredAt), 0).String(), ctx.BlockTime().String())
		}
		return nil
	} else if opNum != sigNum {
		return fmt.Errorf("invalid signature length: expected=%v actual=%v", opNum, sigNum)
	}

	var success uint64 = 0
	for i, op := range operators {
		if len(signatures[i]) == 0 {
			continue
		}
		ek, err := RecoverAddress(commitment, signatures[i])
		if err != nil {
			return err
		}
		ekInfo, err := cs.GetEKInfo(clientStore, ek)
		if err != nil {
			return err
		} else if ekInfo == nil {
			return fmt.Errorf("enclave key '%v' not found", ek)
		} else if ekInfo.IsExpired(ctx.BlockTime()) {
			return fmt.Errorf("enclave key '%v' is expired", ek)
		} else if !ekInfo.IsMatchOperator(op) {
			return fmt.Errorf("enclave key '%v' operator mismatch: expected=%v actual=%v", ek, op, ekInfo.Operator)
		}
		success++
	}

	if success*cs.OperatorsThresholdDenominator < cs.OperatorsThresholdDenominator*uint64(opNum) {
		return fmt.Errorf("insufficient signatures: expected=%v actual=%v", cs.OperatorsThresholdDenominator, success)
	}

	return nil
}

func (cs ClientState) GetOperators() []common.Address {
	var operators []common.Address
	for _, op := range cs.Operators {
		operators = append(operators, common.BytesToAddress(op))
	}
	return operators
}

func (cs ClientState) getKeyExpiration() time.Duration {
	return time.Duration(cs.KeyExpiration) * time.Second
}

func (cs ClientState) isAllowedStatus(status string) bool {
	if status == ias.QuoteOK || status == dcap.UpToDate.String() {
		return true
	}
	for _, s := range cs.AllowedQuoteStatuses {
		if status == s {
			return true
		}
	}
	return false
}

func (cs ClientState) isAllowedAdvisoryIDs(advIDs []string) bool {
	if len(advIDs) == 0 {
		return true
	}
	set := mapset.NewThreadUnsafeSet(cs.AllowedAdvisoryIds...)
	return set.Contains(advIDs...)
}

func (cs ClientState) IsZKDCAPEnabled() bool {
	return len(cs.ZkdcapVerifierInfos) > 0
}

func enclaveKeyPath(key common.Address) []byte {
	return []byte("aux/enclave_keys/" + key.Hex())
}

func risc0MockProofAllowed() bool {
	v := strings.ToLower(os.Getenv("LCP_ZKDCAP_RISC0_MOCK"))
	return v == "1" || v == "true"
}
