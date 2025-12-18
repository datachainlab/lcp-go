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
	elc_updater_grpc "github.com/datachainlab/lcp-go/relay/elcupdater/grpc"
	elc_updater_logger "github.com/datachainlab/lcp-go/relay/elcupdater/logger"
	elc_updater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// Re-export types from storage package for backward compatibility
type ELCUpdateRecord = elc_updater_storage.ELCUpdateRecord
type ELCUpdateStorage = elc_updater_storage.ELCUpdateStorage

// getELCUpdateLogger gets logger for ELC update operations, first from context, then from prover
func getELCUpdateLogger(ctx context.Context, pr *Prover) *log.RelayLogger {
	// First try to get logger from context
	if logger := elc_updater_logger.GetELCUpdaterLoggerOrNil(ctx); logger != nil {
		return logger
	}
	return pr.getLogger()
}

func GetClientStateHeight(ctx context.Context, counterparty core.FinalityAwareChain, height ibcexported.Height) (ibcexported.Height, error) {
	qCtx := core.NewQueryContext(ctx, height)

	csRes, err := counterparty.QueryClientState(qCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get client state: %w", err)
	}

	var cs ibcexported.ClientState
	if err := counterparty.Codec().UnpackAny(csRes.ClientState, &cs); err != nil {
		return nil, fmt.Errorf("failed to unpack client state: %w", err)
	}

	return cs.GetLatestHeight(), nil
}

// getUpdateClientResultsFromGRPC retrieves ELCUpdateResults from gRPC server using height range and returns its updateClientResults property
func getUpdateClientResultsFromGRPC(ctx context.Context, logger *log.RelayLogger, grpcAddress string, targetChain core.Chain, counterparty core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*elc_updater_storage.UpdateClientResult, error) {
	logger.InfoContext(ctx, "using getUpdateClientResults gRPC server", "address", grpcAddress)

	// Get chain ID from target chain and counterparty chain
	chainID := targetChain.ChainID()
	counterpartyChainID := counterparty.ChainID()

	// Get sequential ELCUpdateRecords by height range
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}
	fromHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get client state height from counterparty chain: %w", err)
	}

	records, err := elc_updater_grpc.GetSequentialRecords(ctx, grpcAddress, chainID, counterpartyChainID, fromHeight, latestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to GetSequentialRecords: %w", err)
	}

	var results []*elc_updater_storage.UpdateClientResult
	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
		results = append(results, record.UpdateClientResults...)
	}
	logger.InfoContext(ctx, "retrieved ELCUpdate records from gRPC server",
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"heights", strings.Join(heights, ", "),
	)

	return results, nil
}

func getTipHeightInStorage(ctx context.Context, targetChainID string, counterpartyChainID string, fromHeight ibcexported.Height, storage elc_updater_storage.ELCUpdateStorage, logger *log.RelayLogger) (ibcexported.Height, error) {
	records, err := storage.GetSequence(ctx, targetChainID, counterpartyChainID, fromHeight, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sequential ELCUpdate records: %w", err)
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

		logger.InfoContext(ctx, "Found sequential ELCUpdateRecords",
			"chain_id", targetChainID,
			"counterparty_chain_id", counterpartyChainID,
			"starting_height", fromHeight.String(),
			"records_count", len(records),
			"height_list", heightListStr)
	}

	return records[len(records)-1].ToHeight, nil
}

// SHFUExecuteAndStore executes updateELCForUpdateClient and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for updateClient operations (nil for unspecified)
// counterparty: the counterparty chain object
func (pr *Prover) UpdateELCAndStore(ctx context.Context, counterparty core.FinalityAwareChain, storage elc_updater_storage.ELCUpdateStorage) (*elc_updater_storage.ELCUpdateRecord, error) {
	// Get ELC update logger once and reuse throughout the function
	logger := getELCUpdateLogger(ctx, pr)

	if counterparty == nil {
		return nil, fmt.Errorf("counterparty chain is required for ELC update operations")
	}
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	csHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get ClientState height for ELCUpdateAndStore: %w", err)
	}

	var fromHeight ibcexported.Height
	var dstChain core.FinalityAwareChain
	{
		latestRecord, err := storage.GetLatestSHFUForChain(ctx, pr.originChain.ChainID(), counterparty.ChainID())
		if err != nil {
			return nil, fmt.Errorf("failed to get ClientState height for ELCUpdateAndStore: %w", err)
		}

		if savedTipHeight != nil {
			fromHeight = savedTipHeight
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

	var record *elc_updater_storage.ELCUpdateRecord
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
		record = &elc_updater_storage.ELCUpdateRecord{
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
			logger.ErrorContext(ctx, "Retry attempt for SaveELCUpdateResult due to temporary error", err,
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

// ELCUpdateMockChain is a dummy implementation of core.FinalityAwareChain
// that returns a specific height for testing SetupHeadersForUpdate calls.
// It embeds the interface so unimplemented methods will panic at runtime.
type ELCUpdateMockChain struct {
	core.FinalityAwareChain // Embedded interface - unimplemented methods will panic
	chainID                 string
	latestHeight            ibcexported.Height
	mockClientState         *ELCUpdateMockClientState
}

var (
	_ core.FinalityAwareChain = (*ELCUpdateMockChain)(nil)
)

// ELCUpdateMockClientState is a dummy implementation that embeds ibcexported.ClientState
// All methods will panic at runtime unless specifically implemented
type ELCUpdateMockClientState struct {
	ibcexported.ClientState // Embedded interface - unimplemented methods will panic
	latestHeight            ibcexported.Height
}

var (
	_ ibcexported.ClientState = (*ELCUpdateMockClientState)(nil)
)

// NewELCUpdateMockChain creates a new ELCUpdateMockChain instance
func NewELCUpdateMockChain(chainID string, latestHeight ibcexported.Height, clientStateHeight ibcexported.Height) *ELCUpdateMockChain {
	return &ELCUpdateMockChain{
		chainID:         chainID,
		latestHeight:    latestHeight,
		mockClientState: NewELCUpdateMockClientState(clientStateHeight),
	}
}

// ChainID returns the chain ID
func (c *ELCUpdateMockChain) ChainID() string {
	return c.chainID
}

// LatestHeight returns the latest height with context (allowed method)
func (c *ELCUpdateMockChain) LatestHeight(ctx context.Context) (ibcexported.Height, error) {
	return c.latestHeight, nil
}

// QueryClientState returns a QueryClientStateResponse with mock client state
func (c *ELCUpdateMockChain) QueryClientState(qctx core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
	// Use the existing mock client state
	mockClientState := c.mockClientState

	// Pack the client state into Any type
	clientStateAny, err := types.NewAnyWithValue(mockClientState)
	if err != nil {
		return nil, err
	}

	return &clienttypes.QueryClientStateResponse{
		ClientState: clientStateAny,
	}, nil
}

// NewELCUpdateMockClientState creates a new ELCUpdateMockClientState instance
func NewELCUpdateMockClientState(latestHeight ibcexported.Height) *ELCUpdateMockClientState {
	return &ELCUpdateMockClientState{
		latestHeight: latestHeight,
	}
}

// GetLatestHeight returns the configured latest height
func (s *ELCUpdateMockClientState) GetLatestHeight() ibcexported.Height {
	return s.latestHeight
}
