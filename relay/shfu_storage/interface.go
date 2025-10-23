package shfu_storage

import (
	"context"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
)

// SHFURecord represents a SetupHeadersForUpdate record for persistence
type SHFURecord struct {
	ID                    string                 `json:"id"`
	ChainID               string                 `json:"chain_id"`
	CounterpartyChainID   string                 `json:"counterparty_chain_id"`
	CounterpartyHeight    clienttypes.Height     `json:"counterparty_height"`
	LatestHeight          clienttypes.Height     `json:"latest_height"`
	LatestFinalizedHeight clienttypes.Height     `json:"latest_finalized_height"`
	Headers               []SHFUHeaderRecord     `json:"headers"`
	ErrorMessage          string                 `json:"error_message,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
}

// SHFUHeaderRecord represents a single header in the SHFU result
type SHFUHeaderRecord struct {
	Index        int                `json:"index"`
	Height       clienttypes.Height `json:"height"`
	HeaderType   string             `json:"header_type"`
	HeaderData   []byte             `json:"header_data"`
	ProcessedAt  time.Time          `json:"processed_at"`
	ErrorMessage string             `json:"error_message,omitempty"`
}

// SHFUStorage defines the storage interface for SetupHeadersForUpdate operations
// This interface focuses on use cases rather than CRUD operations
type SHFUStorage interface {
	// SaveSHFUResult saves a SetupHeadersForUpdate execution result
	SaveSHFUResult(ctx context.Context, record *SHFURecord) error

	// FindSHFUByChainAndHeight finds SHFU records for a specific chain and counterparty height range
	FindSHFUByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight, toHeight uint64) ([]*SHFURecord, error)

	// GetLatestSHFUForChainPair retrieves the most recent SHFU record for a chain pair
	GetLatestSHFUForChainPair(ctx context.Context, chainID string, counterpartyChainID string) (*SHFURecord, error)

	// FindSHFUByTimeRange finds SHFU records within a time range
	FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error)

	// FindFailedSHFU finds failed SHFU operations for retry or analysis
	FindFailedSHFU(ctx context.Context, chainID string, limit int) ([]*SHFURecord, error)

	// CleanupOldSHFU removes SHFU records older than the specified duration
	CleanupOldSHFU(ctx context.Context, olderThan time.Duration) (int64, error)

	// Close closes the service and releases any resources
	Close() error
}
