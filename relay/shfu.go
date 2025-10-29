package relay

import (
	"context"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/coreutil"
)

// ExecuteSetupHeadersForUpdate executes SetupHeadersForUpdate0 and returns UpdateClientResult array
// This function can be used by various commands and services
// fromHeight: the starting height for SHFU operations
func SHFUExecuteAndStore(ctx context.Context, target *core.ProvableChain, fromHeight ibcexported.Height, storage shfu_storage.SHFUStorage) (*shfu_storage.SHFURecord, error) {
	// Try to get the finalized header
	latestFinalizedHeader, err := target.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	// Check for existing records with the same chainId, counterpartyChainId, fromHeight, and toHeight
	existingRecords, err := storage.FindSHFUByChainAndHeight(ctx, target.ChainID(), fromHeight, latestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to check existing records: %w", err)
	}
	if len(existingRecords) > 0 {
		return nil, nil
	}

	// Create the height for SHFUMockChain from the specified height
	mockHeight := clienttypes.NewHeight(latestFinalizedHeader.GetHeight().GetRevisionNumber(), fromHeight.GetRevisionHeight())

	// Create a SHFUMockChain instance for counterparty argument
	counterparty := NewSHFUMockChain("mock-counterparty-chain", mockHeight)

	// Try to unwrap the Prover to get the LCP Prover type
	lcpProver, err := coreutil.UnwrapProver[*Prover](target.Prover)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap prover to LCP Prover: %w", err)
	}

	// Call setupHeadersForUpdate0 with the mock counterparty
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
	// Create SHFU record for database storage
	record := &shfu_storage.SHFURecord{
		ChainID:             target.ChainID(),
		FromHeight:          h2h(fromHeight),
		ToHeight:            h2h(latestFinalizedHeader.GetHeight()),
		ToHeightTime:        time.Now(), // Could be extracted from header if available
		UpdatedAt:           time.Now(),
		UpdateClientResults: results,
	}

	// Save the record to database
	err = storage.SaveSHFUResult(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("failed to save SHFU result to database: %w", err)
	}

	fmt.Printf("Successfully saved SHFU result to database for chain %s\n", target.ChainID())

	// Return the saved record
	return record, nil
}

// SHFUMockChain is a dummy implementation of core.FinalityAwareChain
// that returns a specific height for testing SetupHeadersForUpdate calls.
// It embeds the interface so unimplemented methods will panic at runtime.
type SHFUMockChain struct {
	core.FinalityAwareChain // Embedded interface - unimplemented methods will panic
	chainID                 string
	mockClientState         *SHFUMockClientState
}

var (
	_ core.FinalityAwareChain = (*SHFUMockChain)(nil)
)

// SHFUMockClientState is a dummy implementation that embeds ibcexported.ClientState
// All methods will panic at runtime unless specifically implemented
type SHFUMockClientState struct {
	ibcexported.ClientState // Embedded interface - unimplemented methods will panic
	height                  ibcexported.Height
}

var (
	_ ibcexported.ClientState = (*SHFUMockClientState)(nil)
)

// NewSHFUMockChain creates a new SHFUMockChain instance
func NewSHFUMockChain(chainID string, latestHeight ibcexported.Height) *SHFUMockChain {
	return &SHFUMockChain{
		chainID:         chainID,
		mockClientState: NewSHFUMockClientState(latestHeight),
	}
}

// ChainID returns the chain ID
func (c *SHFUMockChain) ChainID() string {
	return c.chainID
}

// LatestHeight returns the latest height with context (allowed method)
func (c *SHFUMockChain) LatestHeight(ctx context.Context) (ibcexported.Height, error) {
	return c.mockClientState.GetLatestHeight(), nil
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
		height: latestHeight,
	}
}

// GetLatestHeight returns the configured latest height
func (s *SHFUMockClientState) GetLatestHeight() ibcexported.Height {
	return s.height
}
