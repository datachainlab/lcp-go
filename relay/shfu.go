package relay

import (
	"context"
	"fmt"
	"time"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/coreutil"
)

// Re-export types from storage package for backward compatibility
type SHFURecord = shfu_storage.SHFURecord
type SHFUStorage = shfu_storage.SHFUStorage

// ExecuteSetupHeadersForUpdate executes SetupHeadersForUpdate0 and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for SHFU operations (nil for unspecified)
// counterparty: the counterparty chain object
func SHFUExecuteAndStore(ctx context.Context, target *core.ProvableChain, counterparty *core.ProvableChain, storage SHFUStorage) (*SHFURecord, error) {
	// Check if counterparty chain is provided
	if counterparty == nil {
		return nil, fmt.Errorf("counterparty chain is required for SHFU operations")
	}

	// Unwrap LCP prover from the chain to get configuration
	lcpProver, err := coreutil.UnwrapProver[*Prover](target.Prover)
	if err != nil {
		return nil, fmt.Errorf("chain %q is not an LCP prover: %w", target.ChainID(), err)
	}

	// Try to get the finalized header
	latestFinalizedHeader, err := target.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	toHeight := latestFinalizedHeader.GetHeight()

	// Check for existing records with the same chainId, counterpartyChainId, fromHeight, and toHeight
	existingRecords, err := storage.FindSHFUByChainAndHeight(ctx, target.ChainID(), counterparty.ChainID(), toHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing records: %w", err)
	}
	if len(existingRecords) > 0 {
		return nil, nil
	}

	// Call setupHeadersForUpdate0 with the counterparty chain
	results, err := lcpProver.setupHeadersForUpdate0(ctx, counterparty, latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to call setupHeadersForUpdate0: %w", err)
	}

	h2h := func(h ibcexported.Height) clienttypes.Height {
		return clienttypes.Height{
			RevisionNumber: h.GetRevisionNumber(),
			RevisionHeight: h.GetRevisionHeight(),
		}
	}

	// Serialize the latestFinalizedHeader (ClientMessage) to bytes
	anyMsg, err := types.NewAnyWithValue(latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to create Any from latestFinalizedHeader: %w", err)
	}

	latestFinalizedHeaderBytes, err := target.Codec().Marshal(anyMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal latestFinalizedHeader: %w", err)
	}

	// Create SHFU record for database storage
	record := &SHFURecord{
		ChainID:               target.ChainID(),
		CounterpartyChainID:   counterparty.ChainID(),
		ToHeight:              h2h(toHeight),
		ToHeightTime:          time.Now(), // Could be extracted from header if available
		UpdatedAt:             time.Now(),
		UpdateClientResults:   results,
		LatestFinalizedHeader: latestFinalizedHeaderBytes,
	}

	fmt.Printf("SHFU executed for target chain %s with counterparty chain %s\n", target.ChainID(), counterparty.ChainID())

	// Save the record to database with retry logic for temporary errors
	err = retry.Do(
		func() error {
			return storage.SaveSHFUResult(ctx, record)
		},
		retry.Context(ctx),
		retry.Attempts(3),
		retry.Delay(100*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.RetryIf(func(err error) bool {
			// Retry only if it's a temporary error according to the storage implementation
			return storage.IsTemporaryError(err)
		}),
		retry.OnRetry(func(n uint, err error) {
			fmt.Printf("Retry attempt %d for SaveSHFUResult due to temporary error: %v\n", n+1, err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save SHFU result to database after retries: %w", err)
	}

	fmt.Printf("Successfully saved SHFU result to database for chain %s\n", target.ChainID())

	// Return the saved record
	return record, nil
}
