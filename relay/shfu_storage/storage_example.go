package shfu_storage

import (
	"context"
	"fmt"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
)

// StorageExample demonstrates how to use the SHFU storage system
func StorageExample() error {
	// Create SQLite storage (use InitSQLiteStorage for new database)
	storage, err := InitSQLiteStorage("./shfu_cache.db")
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}
	defer storage.Close()

	ctx := context.Background()

	// Create a sample SHFU record with UpdateClientResults
	sampleResults := []*UpdateClientResult{
		{
			Message:   []byte("sample_message_1"),
			Signature: []byte("sample_signature_1"),
		},
		{
			Message:   []byte("sample_message_2"),
			Signature: []byte("sample_signature_2"),
		},
	}

	record := &SHFURecord{
		ChainID: "chain-a",
		ToHeight: clienttypes.Height{
			RevisionNumber: 1,
			RevisionHeight: 103,
		},
		ToHeightTime:        time.Now(),
		UpdatedAt:           time.Now(),
		UpdateClientResults: sampleResults,
	}

	// Save the record
	if err := storage.SaveSHFUResult(ctx, record); err != nil {
		return fmt.Errorf("failed to save record: %w", err)
	}

	fmt.Printf("Successfully saved SHFU record for chain %s\n", record.ChainID)

	// Retrieve the latest record for the chain (without counterparty filter)
	latest, err := storage.GetLatestSHFUForChain(ctx, "chain-a", "")
	if err != nil {
		return fmt.Errorf("failed to get latest record: %w", err)
	}

	if latest != nil {
		fmt.Printf("Retrieved latest record for %s, updated at: %s\n",
			latest.ChainID, latest.UpdatedAt.Format(time.RFC3339))
		fmt.Printf("To height time: %s\n", latest.ToHeightTime.Format(time.RFC3339))
	}

	return nil
}
