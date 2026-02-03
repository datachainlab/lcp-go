package storage

import (
	"context"
	"encoding/hex"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
)

// UpdateClientResult represents the result of updateClient operation
type UpdateClientResult struct {
	Message   []byte
	Signature []byte
}

// Record represents a updateClient record for persistence
type Record struct {
	ChainID               string                `json:"chain_id"`
	CounterpartyChainID   string                `json:"counterparty_chain_id"`
	FromHeight            clienttypes.Height    `json:"from_height"`
	ToHeight              clienttypes.Height    `json:"to_height"`
	UpdatedAt             time.Time             `json:"updated_at"`
	UpdateClientResults   []*UpdateClientResult `json:"update_client_results"`
	LatestFinalizedHeader []byte                `json:"latest_finalized_header"` // Serialized core.Header bytes
}

// FormatSummary formats the Record as a map for JSON output
func (r *Record) FormatSummary() map[string]interface{} {
	// Prepare update client results for JSON output
	updateClientResults := make([]map[string]interface{}, len(r.UpdateClientResults))
	for i, result := range r.UpdateClientResults {
		updateClientResults[i] = map[string]interface{}{
			"message_hex":    hex.EncodeToString(result.Message),
			"signature_hex":  hex.EncodeToString(result.Signature),
			"message_size":   len(result.Message),
			"signature_size": len(result.Signature),
		}
	}

	return map[string]interface{}{
		"chain_id":               r.ChainID,
		"from_height":            r.FromHeight,
		"to_height":              r.ToHeight,
		"results_received_count": len(r.UpdateClientResults),
		"update_client_results":  updateClientResults,
		"timestamp":              time.Now().Format(time.RFC3339),
	}
}

// Storage defines the storage interface for updateClient operations
// This interface focuses on use cases rather than CRUD operations
type Storage interface {
	// Save saves a updateClient execution result
	Save(ctx context.Context, record *Record) error

	// FindByChainAndHeight finds records for a specific chain with exact height match
	FindByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight ibcexported.Height, toHeight ibcexported.Height) ([]*Record, error)

	// GetLatestForChain retrieves the most recent record for a chain
	// If counterpartyChainID is empty, it will be ignored in the query
	GetLatestForChain(ctx context.Context, chainID string, counterpartyChainID string) (*Record, error)

	// GetSequential retrieves sequential records starting from the specified height
	// Returns records in chronological order where each record's FromHeight matches the previous record's ToHeight
	// If toHeight is not nil, stops when reaching a record with that ToHeight
	GetSequential(ctx context.Context, chainID string, counterpartyChainID string, fromHeight ibcexported.Height, toHeight ibcexported.Height) ([]*Record, error)

	// List lists records in the database with optional chain ID filters
	List(ctx context.Context, chainID, counterpartyChainID string) ([]*Record, error)

	// Cleanup removes records older than the specified duration
	Cleanup(ctx context.Context, olderThan time.Duration) (int64, error)

	// IsTemporaryError determines if an error is temporary and the operation can be retried
	// Returns true for errors like database locks, connection timeouts, etc.
	// Implementation varies by database type (SQLite, PostgreSQL, etc.)
	IsTemporaryError(err error) bool

	// Close closes the storage connection and releases resources
	Close() error

	// Description returns a description string of the storage implementation
	Description() string
}
