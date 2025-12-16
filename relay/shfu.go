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
	"github.com/datachainlab/lcp-go/relay/shfu_grpc"
	"github.com/datachainlab/lcp-go/relay/shfu_logger"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// Re-export types from storage package for backward compatibility
type SHFURecord = shfu_storage.SHFURecord
type SHFUStorage = shfu_storage.SHFUStorage

// getSHFULogger gets logger for SHFU operations, first from context, then from prover
func (pr *Prover) getSHFULogger(ctx context.Context) *log.RelayLogger {
	// First try to get logger from context
	if logger := shfu_logger.GetSHFULoggerOrNil(ctx); logger != nil {
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

// getUpdateClientFromGRPC retrieves SHFU results from gRPC server using height range
func getUpdateClientsFromGRPC(ctx context.Context, logger *log.RelayLogger, grpcAddress string, targetChain core.Chain, counterparty core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*shfu_storage.UpdateClientResult, error) {
	logger.InfoContext(ctx, "using SHFU gRPC server", "address", grpcAddress)

	// Get chain ID from target chain and counterparty chain
	chainID := targetChain.ChainID()
	counterpartyChainID := counterparty.ChainID()

	// Get SHFU record by height range
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}
	fromHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get client state height from counterparty chain: %w", err)
	}

	records, err := shfu_grpc.GetSequentialSHFURecords(ctx, grpcAddress, chainID, counterpartyChainID, fromHeight, latestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get sequential SHFU records: %w", err)
	}

	var results []*shfu_storage.UpdateClientResult
	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
		results = append(results, record.UpdateClientResults...)
	}
	logger.InfoContext(ctx, "retrieved SHFU records from gRPC server",
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"heights", strings.Join(heights, ", "),
	)

	return results, nil
}

func getTipHeightInStorage(ctx context.Context, targetChainID string, counterpartyChainID string, fromHeight ibcexported.Height, storage SHFUStorage, logger *log.RelayLogger) (ibcexported.Height, error) {
	records, err := storage.GetSequentialSHFURecords(ctx, targetChainID, counterpartyChainID, fromHeight, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sequential SHFU records: %w", err)
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

		logger.InfoContext(ctx, "Found sequential SHFU records",
			"chain_id", targetChainID,
			"counterparty_chain_id", counterpartyChainID,
			"starting_height", fromHeight.String(),
			"records_count", len(records),
			"height_list", heightListStr)
	}

	return records[len(records)-1].ToHeight, nil
}

// ExecuteSetupHeadersForUpdate executes SetupHeadersForUpdate0 and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for SHFU operations (nil for unspecified)
// counterparty: the counterparty chain object
func (pr *Prover) SHFUExecuteAndStore(ctx context.Context, counterparty core.FinalityAwareChain, storage SHFUStorage) (*SHFURecord, error) {
	// Get SHFU logger once and reuse throughout the function
	logger := pr.getSHFULogger(ctx)

	if counterparty == nil {
		return nil, fmt.Errorf("counterparty chain is required for SHFU operations")
	}
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	csHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get ClientState height for SHFUExecuteAndStore: %w", err)
	}

	var fromHeight ibcexported.Height
	var dstChain core.FinalityAwareChain
	{
		savedTipHeight, err := getTipHeightInStorage(ctx, pr.originChain.ChainID(), counterparty.ChainID(), csHeight, storage, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to get ClientState height for SHFUExecuteAndStore: %w", err)
		}

		if savedTipHeight != nil {
			fromHeight = savedTipHeight
			dstChain = NewSHFUMockChain(counterparty.ChainID(), counterpartyLatestFinalizedHeader.GetHeight(), fromHeight)
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
		logger.InfoContext(ctx, "Skipping SHFU execution: already have record with sufficient height",
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
	results, err := pr.setupHeadersForUpdate0(ctx, dstChain, originLatestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to call setupHeadersForUpdate0: %w", err)
	}

	logger.InfoContext(ctx, "SHFU executed successfully",
		"target_chain_id", pr.originChain.ChainID(),
		"counterparty_chain_id", counterparty.ChainID(),
		"latest_finalized_height", originLatestFinalizedHeader.GetHeight().String(),
	)

	var record *SHFURecord
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

		// Create SHFU record for database storage
		record = &SHFURecord{
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
				"chain_id", pr.originChain.ChainID(),
				"counterparty_chain_id", counterparty.ChainID(),
				"from_height", record.FromHeight.String(),
				"to_height", record.ToHeight.String(),
			)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save SHFU result to database after retries: %w", err)
	}

	logger.InfoContext(ctx, "Successfully saved SHFU result to database",
		"chain_id", pr.originChain.ChainID(),
		"counterparty_chain_id", counterparty.ChainID(),
		"from_height", record.FromHeight.String(),
		"to_height", record.ToHeight.String(),
	)

	// Return the saved record
	return record, nil
}

// SHFUMockChain is a dummy implementation of core.FinalityAwareChain
// that returns a specific height for testing SetupHeadersForUpdate calls.
// It embeds the interface so unimplemented methods will panic at runtime.
type SHFUMockChain struct {
	core.FinalityAwareChain // Embedded interface - unimplemented methods will panic
	chainID                 string
	latestHeight            ibcexported.Height
	mockClientState         *SHFUMockClientState
}

var (
	_ core.FinalityAwareChain = (*SHFUMockChain)(nil)
)

// SHFUMockClientState is a dummy implementation that embeds ibcexported.ClientState
// All methods will panic at runtime unless specifically implemented
type SHFUMockClientState struct {
	ibcexported.ClientState // Embedded interface - unimplemented methods will panic
	latestHeight            ibcexported.Height
}

var (
	_ ibcexported.ClientState = (*SHFUMockClientState)(nil)
)

// NewSHFUMockChain creates a new SHFUMockChain instance
func NewSHFUMockChain(chainID string, latestHeight ibcexported.Height, clientStateHeight ibcexported.Height) *SHFUMockChain {
	return &SHFUMockChain{
		chainID:         chainID,
		latestHeight:    latestHeight,
		mockClientState: NewSHFUMockClientState(clientStateHeight),
	}
}

// ChainID returns the chain ID
func (c *SHFUMockChain) ChainID() string {
	return c.chainID
}

// LatestHeight returns the latest height with context (allowed method)
func (c *SHFUMockChain) LatestHeight(ctx context.Context) (ibcexported.Height, error) {
	return c.latestHeight, nil
}

// QueryClientState returns a QueryClientStateResponse with mock client state
func (c *SHFUMockChain) QueryClientState(qctx core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
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

// NewSHFUMockClientState creates a new SHFUMockClientState instance
func NewSHFUMockClientState(latestHeight ibcexported.Height) *SHFUMockClientState {
	return &SHFUMockClientState{
		latestHeight: latestHeight,
	}
}

// GetLatestHeight returns the configured latest height
func (s *SHFUMockClientState) GetLatestHeight() ibcexported.Height {
	return s.latestHeight
}
