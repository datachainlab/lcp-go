package types

import (
	"bytes"
	"fmt"
	"strings"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	ModuleName    = "lcp"
	ClientTypeLCP = "lcp-client"
	MrenclaveSize = 32
)

var _ exported.ClientState = (*ClientState)(nil)

func (cs ClientState) Validate() error {
	if cs.KeyExpiration == 0 {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "`KeyExpiration` must be non-zero")
	}
	if l := len(cs.Mrenclave); l != MrenclaveSize {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "`Mrenclave` length must be %v, but got %v", MrenclaveSize, l)
	}
	return nil
}

func (cs ClientState) ClientType() string {
	return ClientTypeLCP
}

func (cs ClientState) GetLatestHeight() exported.Height {
	return cs.LatestHeight
}

func (cs ClientState) GetTimestampAtHeight(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
) (uint64, error) {
	consState, err := GetConsensusState(clientStore, cdc, height)
	if err != nil {
		return 0, err
	}
	return consState.GetTimestamp(), nil
}

// Initialization function
// Clients must validate the initial consensus state, and may store any client-specific metadata
// necessary for correct light client operation
func (cs ClientState) Initialize(_ sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, consensusState exported.ConsensusState) error {
	if err := cs.Validate(); err != nil {
		return nil
	}
	if !cs.LatestHeight.IsZero() {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "`LatestHeight` must be zero height")
	}
	consState, ok := consensusState.(*ConsensusState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "unexpected consensus state type: expected=%T got=%T", &ConsensusState{}, consensusState)
	}
	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, consState, cs.GetLatestHeight())
	return nil
}

// Status function
// Clients must return their status. Only Active clients are allowed to process packets.
func (cs ClientState) Status(ctx sdk.Context, clientStore storetypes.KVStore, cdc codec.BinaryCodec) exported.Status {
	return exported.Active
}

// Genesis function
func (cs ClientState) ExportMetadata(_ storetypes.KVStore) []exported.GenesisMetadata {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) CheckSubstituteAndUpdateState(
	ctx sdk.Context, cdc codec.BinaryCodec, subjectClientStore,
	substituteClientStore storetypes.KVStore, substituteClient exported.ClientState,
) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyUpgradeAndUpdateState(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore,
	upgradedClient exported.ClientState, upgradedConsState exported.ConsensusState,
	proofUpgradeClient, proofUpgradeConsState []byte,
) error {
	panic("not implemented") // TODO: Implement
}

// Utility function that zeroes out any client customizable fields in client state
// Ledger enforced fields are maintained while all custom fields are zero values
// Used to verify upgrades
func (cs ClientState) ZeroCustomFields() exported.ClientState {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyMembership(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
	value []byte,
) error {
	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	merklePath := path.(commitmenttypes.MerklePath)
	if l := len(merklePath.KeyPath); l != 2 {
		panic(fmt.Errorf("invalid KeyPath length: %v", l))
	}
	prefixBytes := []byte(merklePath.KeyPath[0])
	commitmentPath := []byte(merklePath.KeyPath[1])

	// NOTE: lcp-client-go does not yet support the consensus state verification,
	// so skip a verification if the path represents the consensus state
	// "clients/{client_id}/consensusStates/{height}"
	parts := strings.Split(string(commitmentPath), "/")
	if len(parts) == 4 && parts[0] == string(host.KeyClientStorePrefix) && parts[2] == host.KeyConsensusStatePrefix {
		return nil
	}

	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}
	consensusState, err := GetConsensusState(clientStore, cdc, height)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client: err=%v", err)
	}
	commitmentProof, err := EthABIDecodeCommitmentProof(proof)
	if err != nil {
		return err
	}
	m, err := commitmentProof.GetMessage()
	if err != nil {
		return err
	}
	msg, err := m.GetVerifyMembershipProxyMessage()
	if err != nil {
		return err
	}
	hashedValue := crypto.Keccak256Hash(value)

	if !height.EQ(msg.Height) {
		return errorsmod.Wrapf(ErrInvalidStateCommitment, "invalid height: expected=%v got=%v", height, msg.Height)
	}
	if !bytes.Equal(prefixBytes, msg.Prefix) {
		return errorsmod.Wrapf(ErrInvalidStateCommitment, "invalid prefix: expected=%v got=%v", prefixBytes, msg.Prefix)
	}
	if !bytes.Equal(commitmentPath, msg.Path) {
		return errorsmod.Wrapf(ErrInvalidStateCommitment, "invalid path: expected=%v got=%v", string(commitmentPath), string(msg.Path))
	}
	if hashedValue != msg.Value {
		return errorsmod.Wrapf(ErrInvalidStateCommitment, "invalid value: expected=%X got=%X", hashedValue[:], msg.Value)
	}
	if !msg.StateID.EqualBytes(consensusState.StateId) {
		return errorsmod.Wrapf(ErrInvalidStateCommitment, "invalid state ID: expected=%v got=%v", consensusState.StateId, msg.StateID)
	}
	if err := VerifySignatureWithSignBytes(commitmentProof.Message, commitmentProof.Signature, commitmentProof.Signer); err != nil {
		return errorsmod.Wrapf(ErrInvalidStateCommitmentProof, "failed to verify state commitment proof: %v", err)
	}
	if !cs.IsActiveKey(ctx.BlockTime(), clientStore, commitmentProof.Signer) {
		return errorsmod.Wrapf(ErrExpiredEnclaveKey, "key '%v' has expired", commitmentProof.Signer.Hex())
	}
	return nil
}

// VerifyNonMembership is a generic proof verification method which verifies the absence of a given CommitmentPath at a specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
func (cs ClientState) VerifyNonMembership(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
) error {
	return cs.VerifyMembership(ctx, clientStore, cdc, height, delayTimePeriod, delayBlockPeriod, proof, path, []byte{})
}

// verifyDelayPeriodPassed will ensure that at least delayTimePeriod amount of time and delayBlockPeriod number of blocks have passed
// since consensus state was submitted before allowing verification to continue.
func verifyDelayPeriodPassed(ctx sdk.Context, store storetypes.KVStore, proofHeight exported.Height, delayTimePeriod, delayBlockPeriod uint64) error {
	if delayTimePeriod != 0 {
		// check that executing chain's timestamp has passed consensusState's processed time + delay time period
		processedTime, ok := GetProcessedTime(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedTimeNotFound, "processed time not found for height: %s", proofHeight)
		}

		currentTimestamp := uint64(ctx.BlockTime().UnixNano())
		validTime := processedTime + delayTimePeriod

		// NOTE: delay time period is inclusive, so if currentTimestamp is validTime, then we return no error
		if currentTimestamp < validTime {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until time: %d, current time: %d",
				validTime, currentTimestamp)
		}

	}

	if delayBlockPeriod != 0 {
		// check that executing chain's height has passed consensusState's processed height + delay block period
		processedHeight, ok := GetProcessedHeight(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedHeightNotFound, "processed height not found for height: %s", proofHeight)
		}

		currentHeight := clienttypes.GetSelfHeight(ctx)
		validHeight := clienttypes.NewHeight(processedHeight.GetRevisionNumber(), processedHeight.GetRevisionHeight()+delayBlockPeriod)

		// NOTE: delay block period is inclusive, so if currentHeight is validHeight, then we return no error
		if currentHeight.LT(validHeight) {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until height: %s, current height: %s",
				validHeight, currentHeight)
		}
	}

	return nil
}
