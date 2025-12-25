package relay

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/elcupdater"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// getTipHeightInStorage retrieves the highest ToHeight from sequential records
// stored in the given storage, starting from fromHeight.
// If no records are found, returns nil height.
func getTipHeightInStorage(ctx context.Context, targetChainID string, counterpartyChainID string, fromHeight ibcexported.Height, storage elcupdater_storage.Storage, logger *log.RelayLogger) (ibcexported.Height, error) {
	records, err := storage.GetSequence(ctx, targetChainID, counterpartyChainID, fromHeight, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sequential records: %w", err)
	}

	if len(records) == 0 {
		return nil, nil
	}

	// Log the sequential records found
	if logger != nil {
		// Create comma-separated height list for debugging
		var heightList []string
		for _, record := range records {
			heightList = append(heightList, fmt.Sprintf("%s..%s", record.FromHeight.String(), record.ToHeight.String()))
		}
		heightListStr := strings.Join(heightList, ",")

		logger.InfoContext(ctx, "Found sequential records",
			"chain_id", targetChainID,
			"counterparty_chain_id", counterpartyChainID,
			"starting_height", fromHeight.String(),
			"records_count", len(records),
			"height_list", heightListStr)
	}

	return records[len(records)-1].ToHeight, nil
}

// UpdateELCAndStore executes updateELCForUpdateClient and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for updateClient operations (nil for unspecified)
// counterparty: the counterparty chain object
func (pr *Prover) UpdateELCAndStore(ctx context.Context, counterparty core.FinalityAwareChain, storage elcupdater_storage.Storage) (*elcupdater_storage.Record, error) {
	// Get ELC update logger once and reuse throughout the function
	logger := pr.getLogger()

	if counterparty == nil {
		return nil, fmt.Errorf("counterparty chain is required for ELC update operations")
	}
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	csHeight, err := elcupdater.GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get ClientState height for UpdateELCAndStore: %w", err)
	}

	var fromHeight ibcexported.Height
	var dstChain core.FinalityAwareChain
	{
		savedTipHeight, err := getTipHeightInStorage(ctx, pr.GetOriginChain().ChainID(), counterparty.ChainID(), csHeight, storage, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to get ClientState height for UpdateELCAndStore: %w", err)
		}

		if savedTipHeight != nil {
			fromHeight = savedTipHeight
			dstChain = elcupdater.NewChain(counterparty.ChainID(), counterpartyLatestFinalizedHeader.GetHeight(), fromHeight)
		} else {
			fromHeight = csHeight
			dstChain = counterparty
		}
	}

	originLatestFinalizedHeader, err := pr.originProver.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}
	toHeight := originLatestFinalizedHeader.GetHeight()

	if fromHeight.EQ(toHeight) {
		logger.InfoContext(ctx, "Skipping ELC update execution: already have record with sufficient height",
			"chain_id", pr.originChain.ChainID(),
			"counterparty_chain_id", counterparty.ChainID(),
			"from_height", fromHeight.String(),
			"to_height", toHeight.String(),
		)
		return nil, nil
	}

	if err := pr.UpdateEKIIfNeeded(ctx, counterparty); err != nil {
		return nil, err
	}
	results, err := pr.updateELCForUpdateClient(ctx, dstChain, originLatestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to call updateELCForUpdateClient: %w", err)
	}

	logger.InfoContext(ctx, "ELC update executed successfully",
		"target_chain_id", pr.originChain.ChainID(),
		"counterparty_chain_id", counterparty.ChainID(),
		"latest_finalized_height", originLatestFinalizedHeader.GetHeight().String(),
	)

	var record *elcupdater_storage.Record
	{
		h2h := func(h ibcexported.Height) clienttypes.Height {
			return clienttypes.Height{
				RevisionNumber: h.GetRevisionNumber(),
				RevisionHeight: h.GetRevisionHeight(),
			}
		}

		// Serialize the latestFinalizedHeader (ClientMessage) to bytes
		anyMsg, err := types.NewAnyWithValue(originLatestFinalizedHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to create Any from originLatestFinalizedHeader: %w", err)
		}

		latestFinalizedHeaderBytes, err := pr.originChain.Codec().Marshal(anyMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal originLatestFinalizedHeader: %w", err)
		}

		// Create ELC update record for database storage
		record = &elcupdater_storage.Record{
			ChainID:               pr.originChain.ChainID(),
			CounterpartyChainID:   counterparty.ChainID(),
			FromHeight:            h2h(fromHeight),
			ToHeight:              h2h(toHeight),
			UpdatedAt:             time.Now(),
			UpdateClientResults:   results,
			LatestFinalizedHeader: latestFinalizedHeaderBytes,
		}
	}

	// Save the record to database with retry logic for temporary errors
	err = retry.Do(
		func() error {
			return storage.Save(ctx, record)
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
			logger.ErrorContext(ctx, "Retry attempt for Save due to temporary error", err,
				"attempt", n+1,
				"chain_id", pr.originChain.ChainID(),
				"counterparty_chain_id", counterparty.ChainID(),
				"from_height", record.FromHeight.String(),
				"to_height", record.ToHeight.String(),
			)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save ELC update result to database after retries: %w", err)
	}

	logger.InfoContext(ctx, "Successfully saved ELC update result to database",
		"chain_id", pr.originChain.ChainID(),
		"counterparty_chain_id", counterparty.ChainID(),
		"from_height", record.FromHeight.String(),
		"to_height", record.ToHeight.String(),
	)

	// Return the saved record
	return record, nil
}
