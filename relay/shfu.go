package relay

import (
	"context"
	"fmt"
	"time"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_logger"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/coreutil"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// Re-export types from storage package for backward compatibility
type SHFURecord = shfu_storage.SHFURecord
type SHFUStorage = shfu_storage.SHFUStorage

// getSHFULogger gets logger for SHFU operations, first from context, then from prover
func getSHFULogger(ctx context.Context, target *core.ProvableChain) *log.RelayLogger {
	// First try to get logger from context
	if logger := shfu_logger.GetSHFULoggerOrNil(ctx); logger != nil {
		return logger
	}

	// If no logger in context, try to get from prover
	if lcpProver, err := coreutil.UnwrapProver[*Prover](target.Prover); err == nil {
		return lcpProver.getLogger()
	}

	// Fallback to default SHFU logger
	return shfu_logger.GetSHFULogger(ctx)
}

// ExecuteSetupHeadersForUpdate executes SetupHeadersForUpdate0 and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for SHFU operations (nil for unspecified)
// counterparty: the counterparty chain object
func SHFUExecuteAndStore(ctx context.Context, target *core.ProvableChain, counterparty *core.ProvableChain, storage SHFUStorage) (*SHFURecord, error) {
	// Get SHFU logger once and reuse throughout the function
	logger := getSHFULogger(ctx, target)

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

	// Check if we already have a record with toHeight >= current toHeight
	latestRecord, err := storage.GetLatestSHFUForChain(ctx, target.ChainID(), counterparty.ChainID())
	if err != nil {
		return nil, fmt.Errorf("failed to get latest SHFU record: %w", err)
	}
	if latestRecord != nil && !latestRecord.ToHeight.LT(toHeight) {
		// We already have a record with toHeight >= current toHeight, so skip execution
		logger.InfoContext(ctx, "Skipping SHFU execution: already have record with sufficient height",
			"chain_id", target.ChainID(),
			"counterparty_chain_id", counterparty.ChainID(),
			"current_to_height", toHeight.String(),
			"existing_to_height", latestRecord.ToHeight.String())
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

	logger.InfoContext(ctx, "SHFU executed successfully",
		"target_chain_id", target.ChainID(),
		"counterparty_chain_id", counterparty.ChainID())

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
			logger.ErrorContext(ctx, "Retry attempt for SaveSHFUResult due to temporary error", err,
				"attempt", n+1,
				"target_chain_id", target.ChainID())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save SHFU result to database after retries: %w", err)
	}

	logger.InfoContext(ctx, "Successfully saved SHFU result to database",
		"target_chain_id", target.ChainID(),
		"counterparty_chain_id", counterparty.ChainID())

	// Return the saved record
	return record, nil
}
