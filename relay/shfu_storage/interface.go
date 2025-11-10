package shfu_storage

import (
	"context"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
)

// UpdateClientResult represents the result of updateClient operation
type UpdateClientResult struct {
	Message   []byte
	Signature []byte
}

// SHFURecord represents a SetupHeadersForUpdate record for persistence
type SHFURecord struct {
	ChainID             string                `json:"chain_id"`
	FromHeight          clienttypes.Height    `json:"from_height"`
	ToHeight            clienttypes.Height    `json:"to_height"`
	ToHeightTime        time.Time             `json:"to_height_time"`
	UpdatedAt           time.Time             `json:"updated_at"`
	UpdateClientResults []*UpdateClientResult `json:"update_client_results"`
	ClientMessageBytes  []byte                `json:"client_message_bytes"` // Serialized ClientMessage bytes
}

// SHFUStorage defines the storage interface for SetupHeadersForUpdate operations
// This interface focuses on use cases rather than CRUD operations
type SHFUStorage interface {
	// SaveSHFUResult saves a SetupHeadersForUpdate execution result
	SaveSHFUResult(ctx context.Context, record *SHFURecord) error

	// FindSHFUByChainAndHeight finds SHFU records for a specific chain with exact height match
	FindSHFUByChainAndHeight(ctx context.Context, chainID string, fromHeight, toHeight ibcexported.Height) ([]*SHFURecord, error)

	// GetLatestSHFUForChain retrieves the most recent SHFU record for a chain
	GetLatestSHFUForChain(ctx context.Context, chainID string) (*SHFURecord, error)

	// FindSHFUByTimeRange finds SHFU records within a time range
	FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error)

	// ListAllSHFURecords lists all SHFU records in the database
	ListAllSHFURecords(ctx context.Context) ([]*SHFURecord, error)

	// CleanupOldSHFU removes SHFU records older than the specified duration
	CleanupOldSHFU(ctx context.Context, olderThan time.Duration) (int64, error)

	// Close closes the service and releases any resources
	Close() error
}
