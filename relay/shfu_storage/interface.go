package shfu_storage

import (
	"context"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
)

// UpdateClientResult represents the result of updateClient operation
type UpdateClientResult struct {
	Message   []byte
	Signature []byte
}

// SHFURecord represents a SetupHeadersForUpdate record for persistence
type SHFURecord struct {
	ChainID                   string                `json:"chain_id"`
	CounterpartyChainID       string                `json:"counterparty_chain_id"`
	FromHeight                clienttypes.Height    `json:"from_height"`
	LatestFinalizedHeight     clienttypes.Height    `json:"latest_finalized_height"`
	LatestFinalizedHeightTime time.Time             `json:"latest_finalized_height_time"`
	UpdatedAt                 time.Time             `json:"updated_at"`
	UpdateClientResults       []*UpdateClientResult `json:"update_client_results"`
}

// SHFUStorage defines the storage interface for SetupHeadersForUpdate operations
// This interface focuses on use cases rather than CRUD operations
type SHFUStorage interface {
	// SaveSHFUResult saves a SetupHeadersForUpdate execution result
	SaveSHFUResult(ctx context.Context, record *SHFURecord) error

	// FindSHFUByChainAndHeight finds SHFU records for a specific chain and from height range
	FindSHFUByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight, toHeight uint64) ([]*SHFURecord, error)

	// GetLatestSHFUForChainPair retrieves the most recent SHFU record for a chain pair
	GetLatestSHFUForChainPair(ctx context.Context, chainID string, counterpartyChainID string) (*SHFURecord, error)

	// FindSHFUByTimeRange finds SHFU records within a time range
	FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error)

	// ListAllSHFURecords lists all SHFU records in the database
	ListAllSHFURecords(ctx context.Context) ([]*SHFURecord, error)

	// CleanupOldSHFU removes SHFU records older than the specified duration
	CleanupOldSHFU(ctx context.Context, olderThan time.Duration) (int64, error)

	// Close closes the service and releases any resources
	Close() error
}
