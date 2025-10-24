package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/coreutil"
)

// SHFUUpdateClientCacheOptions holds options for update client cache operations
type SHFUUpdateClientCacheOptions struct {
	DBPath string
	Height uint64
	Force  bool
}

// SHFUUpdateClientServerOptions holds options for update client server
type SHFUUpdateClientServerOptions struct {
	DBPath         string
	GRPCAddr       string
	UpdateInterval time.Duration
	CacheSize      int
}

// SHFUQueryLCPOptions holds options for query LCP operations
type SHFUQueryLCPOptions struct {
	Height uint64
}

// SHFUQueryChainOptions holds options for query chain operations
type SHFUQueryChainOptions struct {
	PathName  string
	ChannelID string
}

// SHFUCacheUpdateClient executes SetupHeadersForUpdate and stores the result in SQLite cache
func SHFUCacheUpdateClient(ctx context.Context, target *core.ProvableChain, opts SHFUUpdateClientCacheOptions) error {
	fmt.Printf("CacheUpdateClient called with options: %+v\n", opts)
	return fmt.Errorf("not implemented yet")
}

// SHFUStartUpdateClientServer starts a gRPC server for update client operations
func SHFUStartUpdateClientServer(ctx context.Context, target *core.ProvableChain, opts SHFUUpdateClientServerOptions) error {
	// TODO: Implement gRPC server functionality
	fmt.Printf("StartUpdateClientServer called with options: %+v\n", opts)
	return fmt.Errorf("not implemented yet")
}

// SHFUQueryChain queries chain information including latest consensus state
func SHFUQueryChain(ctx context.Context, target *core.ProvableChain, clientCtx client.Context, opts SHFUQueryChainOptions) error {
	fmt.Printf("QueryChain called with options: %+v\n", opts)
	fmt.Printf("Target chain: %s\n", target.ChainID())

	// Get the latest height from the target chain
	latestHeight, err := target.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest height: %w", err)
	}

	// Try to get the finalized header
	latestFinalizedHeader, err := target.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	fmt.Printf("Latest finalized header height: %d\n", latestFinalizedHeader.GetHeight().GetRevisionHeight())

	var latestConsensusInfo interface{}

	// Try to query the client state using yui-relayer's QueryClientState
	// This uses the target chain's own RPC client instead of cosmos-sdk's offline client
	qctx := core.NewQueryContext(ctx, latestHeight)
	if clientStateRes, err := target.QueryClientState(qctx); err != nil {
		// If QueryClientState fails, just note the error but continue
		latestConsensusInfo = map[string]interface{}{
			"error": err.Error(),
			"note":  "Failed to query client state from yui-relayer",
		}
	} else {
		// Unpack the ClientState from Any using target chain's codec
		var clientState ibcexported.ClientState
		if err := target.Codec().UnpackAny(clientStateRes.ClientState, &clientState); err != nil {
			latestConsensusInfo = map[string]interface{}{
				"error": fmt.Sprintf("Failed to unpack client state: %v", err),
				"note":  "Could not decode ClientState from Any",
			}
		} else {
			// Extract information from the unpacked client state
			latestHeight := clientState.GetLatestHeight()
			latestConsensusInfo = map[string]interface{}{
				"proof_height": clientStateRes.ProofHeight,
				"client_state_info": map[string]interface{}{
					"chain_id":          opts.PathName,
					"channel_id":        opts.ChannelID,
					"client_state_type": fmt.Sprintf("%T", clientState),
					"latest_height_from_client": map[string]interface{}{
						"revision_number": latestHeight.GetRevisionNumber(),
						"revision_height": latestHeight.GetRevisionHeight(),
					},
					"latest_height_from_proof": map[string]interface{}{
						"revision_number": clientStateRes.ProofHeight.RevisionNumber,
						"revision_height": clientStateRes.ProofHeight.RevisionHeight,
					},
				},
			}
		}
	}

	result := map[string]interface{}{
		"chain_id":                       target.ChainID(),
		"path_name":                      opts.PathName,
		"channel_id":                     opts.ChannelID,
		"latest_height":                  latestHeight.GetRevisionHeight(),
		"latest_finalized_header_height": latestFinalizedHeader.GetHeight().GetRevisionHeight(),
		"latest_consensus_state":         latestConsensusInfo,
		"message":                        "Chain information displayed with LatestConsensusState and path info",
		"success":                        true,
		"timestamp":                      time.Now().Format(time.RFC3339),
	}

	// Convert result to JSON string and output
	resultBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	fmt.Printf("Chain information with LatestConsensusState:\n%s\n", string(resultBytes))
	return nil
}

// QueryLCP executes the existing SetupHeadersForUpdate call for testing purposes
func SHFUQueryLCP(ctx context.Context, target *core.ProvableChain, opts SHFUQueryLCPOptions) error {
	fmt.Printf("QueryLCP called with options: %+v\n", opts)
	fmt.Printf("Target chain: %s\n", target.ChainID())

	// Get the latest height from the target chain
	latestHeight, err := target.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest height: %w", err)
	}

	// Try to get the finalized header
	latestFinalizedHeader, err := target.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	fmt.Printf("Latest finalized header height: %d\n", latestFinalizedHeader.GetHeight().GetRevisionHeight())

	// Create the height for SHFUMockChain from the specified height
	mockHeight := clienttypes.NewHeight(latestHeight.GetRevisionNumber(), opts.Height)

	fmt.Printf("Using mock counterparty height: %d\n", mockHeight.GetRevisionHeight())

	// Use ExecuteSetupHeadersForUpdate to get UpdateClientResult array
	results, err := SHFUExecuteSetupHeadersForUpdate(ctx, target, opts.Height)
	if err != nil {
		return fmt.Errorf("failed to execute SetupHeadersForUpdate: %w", err)
	}

	// Process the results
	fmt.Printf("Received %d updateClient results\n", len(results))
	for i, result := range results {
		fmt.Printf("Result %d: message_size=%d bytes, signature_size=%d bytes\n",
			i+1,
			len(result.Message),
			len(result.Signature))
	}
	resultCount := len(results)

	// Create a result with chain and header information
	result := map[string]interface{}{
		"chain_id":                       target.ChainID(),
		"latest_height":                  latestHeight.GetRevisionHeight(),
		"latest_finalized_header_height": latestFinalizedHeader.GetHeight().GetRevisionHeight(),
		"mock_counterparty_height":       mockHeight.GetRevisionHeight(),
		"results_received_count":         resultCount,
		"message":                        "ExecuteSetupHeadersForUpdate called successfully",
		"success":                        true,
		"timestamp":                      time.Now().Format(time.RFC3339),
	}

	// Add the requested height info
	result["target_height"] = latestHeight.GetRevisionHeight()
	result["requested_height"] = opts.Height
	result["actual_height_used"] = opts.Height

	// Convert result to JSON string and output
	resultBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	fmt.Printf("SetupHeadersForUpdate0 result:\n%s\n", string(resultBytes))
	return nil
}

// ExecuteSetupHeadersForUpdate executes SetupHeadersForUpdate0 and returns UpdateClientResult array
// This function can be used by various commands and services
func SHFUExecuteSetupHeadersForUpdate(ctx context.Context, target *core.ProvableChain, counterpartyHeight uint64) ([]*UpdateClientResult, error) {
	// Get the latest height from the target chain
	latestHeight, err := target.LatestHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest height: %w", err)
	}

	// Try to get the finalized header
	latestFinalizedHeader, err := target.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}

	// Create the height for SHFUMockChain from the specified height
	mockHeight := clienttypes.NewHeight(latestHeight.GetRevisionNumber(), counterpartyHeight)

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

	// Return the UpdateClientResult array directly
	return results, nil
}

// SHFUResult represents the result of a SetupHeadersForUpdate execution
// This is the internal working type, separate from storage.SHFURecord
type SHFUResult struct {
	ChainID               string             `json:"chain_id"`
	CounterpartyHeight    clienttypes.Height `json:"counterparty_height"`
	LatestHeight          ibcexported.Height `json:"latest_height"`
	LatestFinalizedHeight ibcexported.Height `json:"latest_finalized_height"`
	Headers               []SHFUHeaderResult `json:"headers"`
	Status                string             `json:"status"`
	ErrorMessage          string             `json:"error_message,omitempty"`
	ExecutedAt            time.Time          `json:"executed_at"`
}

// SHFUHeaderResult represents a single header result
type SHFUHeaderResult struct {
	Index       int                `json:"index"`
	Height      ibcexported.Height `json:"height"`
	HeaderType  string             `json:"header_type"`
	Header      core.Header        `json:"-"` // Don't serialize the actual header
	ProcessedAt time.Time          `json:"processed_at"`
}

// ToStorageRecord converts SHFUResult to storage.SHFURecord for persistence
func (r *SHFUResult) ToStorageRecord() *SHFURecord {
	headers := make([]SHFUHeaderRecord, len(r.Headers))
	for i, h := range r.Headers {
		// Convert header to bytes if needed
		var headerData []byte
		if h.Header != nil {
			// This would need proper serialization based on header type
			headerData = []byte(fmt.Sprintf("header_%d", h.Index))
		}

		headers[i] = SHFUHeaderRecord{
			Index:        h.Index,
			Height:       clienttypes.Height{RevisionNumber: h.Height.GetRevisionNumber(), RevisionHeight: h.Height.GetRevisionHeight()},
			HeaderType:   h.HeaderType,
			HeaderData:   headerData,
			ProcessedAt:  h.ProcessedAt,
			ErrorMessage: "",
		}
	}

	return &SHFURecord{
		ID:                    fmt.Sprintf("%s_%d_%d", r.ChainID, r.CounterpartyHeight.RevisionNumber, r.CounterpartyHeight.RevisionHeight),
		ChainID:               r.ChainID,
		CounterpartyChainID:   "unknown", // This would need to be provided
		CounterpartyHeight:    r.CounterpartyHeight,
		LatestHeight:          clienttypes.Height{RevisionNumber: r.LatestHeight.GetRevisionNumber(), RevisionHeight: r.LatestHeight.GetRevisionHeight()},
		LatestFinalizedHeight: clienttypes.Height{RevisionNumber: r.LatestFinalizedHeight.GetRevisionNumber(), RevisionHeight: r.LatestFinalizedHeight.GetRevisionHeight()},
		Headers:               headers,
		ErrorMessage:          r.ErrorMessage,
		CreatedAt:             r.ExecutedAt,
		UpdatedAt:             r.ExecutedAt,
		Metadata: map[string]interface{}{
			"status": r.Status,
		},
	}
}

// SHFUMockChain is a dummy implementation of core.FinalityAwareChain
// that returns a specific height for testing SetupHeadersForUpdate calls.
// It embeds the interface so unimplemented methods will panic at runtime.
type SHFUMockChain struct {
	core.FinalityAwareChain // Embedded interface - unimplemented methods will panic
	chainID                 string
	latestHeight            ibcexported.Height
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
func NewSHFUMockChain(chainID string, latestHeight ibcexported.Height) *SHFUMockChain {
	return &SHFUMockChain{
		chainID:      chainID,
		latestHeight: latestHeight,
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
	// Get height from query context
	height := qctx.Height()
	mockClientState := NewSHFUMockClientState(height)

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
