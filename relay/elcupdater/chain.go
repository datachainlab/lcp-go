package elcupdater

import (
	"context"

	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/hyperledger-labs/yui-relayer/core"
)

// ELCUpdateMockClientState is a dummy implementation that embeds ibcexported.ClientState
// All methods will panic at runtime unless specifically implemented
type ClientState struct {
	ibcexported.ClientState // Embedded interface - unimplemented methods will panic
	latestHeight            ibcexported.Height
}

// Chain is a dummy implementation of core.FinalityAwareChain
// that returns a specific height for testing SetupHeadersForUpdate calls.
// It embeds the interface so unimplemented methods will panic at runtime.
type Chain struct {
	core.FinalityAwareChain // Embedded interface - unimplemented methods will panic
	chainID                 string
	latestHeight            ibcexported.Height
	mockClientState         *ClientState
}

var (
	_ ibcexported.ClientState = (*ClientState)(nil)
	_ core.FinalityAwareChain = (*Chain)(nil)
)

// NewChain creates a new Chain instance
func NewChain(chainID string, latestHeight ibcexported.Height, clientStateHeight ibcexported.Height) *Chain {
	return &Chain{
		chainID:         chainID,
		latestHeight:    latestHeight,
		mockClientState: NewClientState(clientStateHeight),
	}
}

// ChainID returns the chain ID
func (c *Chain) ChainID() string {
	return c.chainID
}

// LatestHeight returns the latest height with context (allowed method)
func (c *Chain) LatestHeight(ctx context.Context) (ibcexported.Height, error) {
	return c.latestHeight, nil
}

// QueryClientState returns a QueryClientStateResponse with mock client state
func (c *Chain) QueryClientState(qctx core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
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

// NewClientState creates a new ClientState instance
func NewClientState(latestHeight ibcexported.Height) *ClientState {
	return &ClientState{
		latestHeight: latestHeight,
	}
}

// GetLatestHeight returns the configured latest height
func (s *ClientState) GetLatestHeight() ibcexported.Height {
	return s.latestHeight
}
