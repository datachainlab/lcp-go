package types

import (
	"reflect"
	"strings"

	errorsmod "cosmossdk.io/errors"
	storeprefix "cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
)

var (
	// KeyProcessedTime is appended to consensus state key to store the processed time
	KeyProcessedTime = []byte("/processedTime")
	// KeyProcessedHeight is appended to consensus state key to store the processed height
	KeyProcessedHeight = []byte("/processedHeight")
)

// setClientState stores the client state
func setClientState(clientStore storetypes.KVStore, cdc codec.BinaryCodec, clientState *ClientState) {
	key := host.ClientStateKey()
	val := clienttypes.MustMarshalClientState(cdc, clientState)
	clientStore.Set(key, val)
}

// setConsensusState stores the consensus state at the given height.
func setConsensusState(clientStore storetypes.KVStore, cdc codec.BinaryCodec, consensusState *ConsensusState, height exported.Height) {
	key := host.ConsensusStateKey(height)
	val := clienttypes.MustMarshalConsensusState(cdc, consensusState)
	clientStore.Set(key, val)
}

// GetConsensusState retrieves the consensus state from the client prefixed
// store. An error is returned if the consensus state does not exist.
func GetConsensusState(store storetypes.KVStore, cdc codec.BinaryCodec, height exported.Height) (*ConsensusState, error) {
	bz := store.Get(host.ConsensusStateKey(height))
	if bz == nil {
		return nil, errorsmod.Wrapf(
			clienttypes.ErrConsensusStateNotFound,
			"consensus state does not exist for height %s", height,
		)
	}

	consensusStateI, err := clienttypes.UnmarshalConsensusState(cdc, bz)
	if err != nil {
		return nil, errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "unmarshal error: %v", err)
	}

	consensusState, ok := consensusStateI.(*ConsensusState)
	if !ok {
		return nil, errorsmod.Wrapf(
			clienttypes.ErrInvalidConsensus,
			"invalid consensus type %T, expected %T", consensusState, &ConsensusState{},
		)
	}

	return consensusState, nil
}

// ProcessedTimeKey returns the key under which the processed time will be stored in the client store.
func ProcessedTimeKey(height exported.Height) []byte {
	return append(host.ConsensusStateKey(height), KeyProcessedTime...)
}

// SetProcessedTime stores the time at which a header was processed and the corresponding consensus state was created.
// This is useful when validating whether a packet has reached the time specified delay period in the tendermint client's
// verification functions
func SetProcessedTime(clientStore storetypes.KVStore, height exported.Height, timeNs uint64) {
	key := ProcessedTimeKey(height)
	val := sdk.Uint64ToBigEndian(timeNs)
	clientStore.Set(key, val)
}

// GetProcessedTime gets the time (in nanoseconds) at which this chain received and processed a tendermint header.
// This is used to validate that a received packet has passed the time delay period.
func GetProcessedTime(clientStore storetypes.KVStore, height exported.Height) (uint64, bool) {
	key := ProcessedTimeKey(height)
	bz := clientStore.Get(key)
	if bz == nil {
		return 0, false
	}
	return sdk.BigEndianToUint64(bz), true
}

// deleteProcessedTime deletes the processedTime for a given height
func deleteProcessedTime(clientStore storetypes.KVStore, height exported.Height) {
	key := ProcessedTimeKey(height)
	clientStore.Delete(key)
}

// ProcessedHeightKey returns the key under which the processed height will be stored in the client store.
func ProcessedHeightKey(height exported.Height) []byte {
	return append(host.ConsensusStateKey(height), KeyProcessedHeight...)
}

// SetProcessedHeight stores the height at which a header was processed and the corresponding consensus state was created.
// This is useful when validating whether a packet has reached the specified block delay period in the tendermint client's
// verification functions
func SetProcessedHeight(clientStore storetypes.KVStore, consHeight, processedHeight exported.Height) {
	key := ProcessedHeightKey(consHeight)
	val := []byte(processedHeight.String())
	clientStore.Set(key, val)
}

// GetProcessedHeight gets the height at which this chain received and processed a tendermint header.
// This is used to validate that a received packet has passed the block delay period.
func GetProcessedHeight(clientStore storetypes.KVStore, height exported.Height) (exported.Height, bool) {
	key := ProcessedHeightKey(height)
	bz := clientStore.Get(key)
	if bz == nil {
		return nil, false
	}
	processedHeight, err := clienttypes.ParseHeight(string(bz))
	if err != nil {
		return nil, false
	}
	return processedHeight, true
}

// deleteProcessedHeight deletes the processedHeight for a given height
func deleteProcessedHeight(clientStore storetypes.KVStore, height exported.Height) {
	key := ProcessedHeightKey(height)
	clientStore.Delete(key)
}

// getClientID extracts and validates the clientID from the clientStore's prefix.
//
// Due to the 02-client module not passing the clientID to the lcp module,
// this function was devised to infer it from the store's prefix.
// The expected format of the clientStore prefix is "<placeholder>/{clientID}/".
// If the clientStore is of type migrateProposalWrappedStore, the subjectStore's prefix is utilized instead.
func getClientID(clientStore storetypes.KVStore) (string, error) {
	store, ok := clientStore.(storeprefix.Store)
	if !ok {
		return "", errorsmod.Wrap(ErrRetrieveClientID, "clientStore is not a prefix store")
	}

	// using reflect to retrieve the private prefix field
	r := reflect.ValueOf(&store).Elem()

	f := r.FieldByName("prefix")
	if !f.IsValid() {
		return "", errorsmod.Wrap(ErrRetrieveClientID, "prefix field not found")
	}

	prefix := string(f.Bytes())

	split := strings.Split(prefix, "/")
	if len(split) < 3 {
		return "", errorsmod.Wrap(ErrRetrieveClientID, "prefix is not of the expected form")
	}

	// the clientID is the second to last element of the prefix
	// the prefix is expected to be of the form "<placeholder>/{clientID}/"
	clientID := split[len(split)-2]
	if err := ValidateClientID(clientID); err != nil {
		return "", errorsmod.Wrapf(ErrRetrieveClientID, "prefix does not contain a valid clientID: %s", err.Error())
	}

	return clientID, nil
}

// ValidateClientID validates the client identifier by ensuring that it conforms
// to the 02-client identifier format and that it is a lcp clientID.
func ValidateClientID(clientID string) error {
	if !clienttypes.IsValidClientID(clientID) {
		return errorsmod.Wrapf(host.ErrInvalidID, "invalid client identifier %s", clientID)
	}

	if !strings.HasPrefix(clientID, ClientTypeLCP) {
		return errorsmod.Wrapf(host.ErrInvalidID, "client identifier %s does not contain %s prefix", clientID, ClientTypeLCP)
	}

	return nil
}
