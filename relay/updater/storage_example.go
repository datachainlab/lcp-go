package updater

import (
	"context"
	"fmt"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/updater/storage"
)

// StorageExample demonstrates how to use the SHFU storage system
func StorageExample() error {
	// Create SQLite storage
	storage, err := storage.NewSQLiteStorage("./shfu_cache.db")
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Create a sample SHFU record
	record := &SHFURecord{
		ID:                  "example_record_1",
		ChainID:             "chain-a",
		CounterpartyChainID: "chain-b",
		CounterpartyHeight: clienttypes.Height{
			RevisionNumber: 1,
			RevisionHeight: 100,
		},
		LatestHeight: clienttypes.Height{
			RevisionNumber: 1,
			RevisionHeight: 105,
		},
		LatestFinalizedHeight: clienttypes.Height{
			RevisionNumber: 1,
			RevisionHeight: 103,
		},
		Headers: []SHFUHeaderRecord{
			{
				Index: 0,
				Height: clienttypes.Height{
					RevisionNumber: 1,
					RevisionHeight: 101,
				},
				HeaderType:  "mock_header",
				HeaderData:  []byte("mock header data"),
				ProcessedAt: time.Now(),
			},
		},
		ErrorMessage: "",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata: map[string]interface{}{
			"source":  "storage_example",
			"version": "1.0",
		},
	}

	// Save the record
	if err := storage.SaveSHFUResult(ctx, record); err != nil {
		return fmt.Errorf("failed to save record: %w", err)
	}

	fmt.Printf("Successfully saved SHFU record: %s\n", record.ID)

	// Retrieve the latest record for the chain pair
	latest, err := storage.GetLatestSHFUForChainPair(ctx, "chain-a", "chain-b")
	if err != nil {
		return fmt.Errorf("failed to get latest record: %w", err)
	}

	if latest != nil {
		fmt.Printf("Retrieved latest record: %s, created at: %s\n",
			latest.ID, latest.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Record has %d headers\n", len(latest.Headers))
	}

	return nil
}
