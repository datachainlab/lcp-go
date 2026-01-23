package storage

import (
	"context"
	"os"
	"testing"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStorageBasicOperations demonstrates and tests basic storage operations
func TestStorageBasicOperations(t *testing.T) {
	// Create temporary database file for testing
	dbPath := "./test_elc_update_storage.db"
	defer os.Remove(dbPath) // Clean up after test
	// Create SQLite storage (use InitSQLiteStorage for new database)
	ctx := context.Background()
	sto, err := InitSQLiteStorage(ctx, dbPath)
	require.NoError(t, err, "failed to create storage")
	defer sto.Close()

	// Create a sample Record with UpdateClientResults
	sampleResults := []*UpdateClientResult{
		{
			Message:   []byte("sample_message_1"),
			Signature: []byte("sample_signature_1"),
			Signer:    []byte("sample_signer_1"),
		},
		{
			Message:   []byte("sample_message_2"),
			Signature: []byte("sample_signature_2"),
			Signer:    []byte("sample_signer_2"),
		},
	}

	record := &Record{
		ChainID:             "chain-a",
		CounterpartyChainID: "chain-b",
		ToHeight: clienttypes.Height{
			RevisionNumber: 1,
			RevisionHeight: 103,
		},
		UpdatedAt:           time.Now(),
		UpdateClientResults: sampleResults,
	}

	// Test saving the record
	err = sto.Save(ctx, record)
	require.NoError(t, err, "failed to save record")

	t.Logf("Successfully saved record for chain %s", record.ChainID)

	// Test retrieving the latest record for the chain (without counterparty filter)
	latest, err := sto.GetLatestForChain(ctx, "chain-a", "")
	require.NoError(t, err, "failed to get latest record")

	// Verify the retrieved record
	require.NotNil(t, latest, "latest record should not be nil")
	assert.Equal(t, "chain-a", latest.ChainID)
	assert.Equal(t, "chain-b", latest.CounterpartyChainID)
	assert.Equal(t, uint64(1), latest.ToHeight.RevisionNumber)
	assert.Equal(t, uint64(103), latest.ToHeight.RevisionHeight)
	assert.Len(t, latest.UpdateClientResults, 2)

	t.Logf("Retrieved latest record for %s, updated at: %s",
		latest.ChainID, latest.UpdatedAt.Format(time.RFC3339))
}

// TestStorageFileExistsError tests that InitSQLiteStorage fails when file already exists
func TestStorageFileExistsError(t *testing.T) {
	// Create a database file first
	dbPath := "./test_existing_db.db"
	defer os.Remove(dbPath) // Clean up after test

	// Initialize database first time (should succeed)
	ctx := context.Background()
	storage1, err := InitSQLiteStorage(ctx, dbPath)
	require.NoError(t, err, "first initialization should succeed")
	storage1.Close()

	// Try to initialize the same file again (should fail)
	storage2, err := InitSQLiteStorage(ctx, dbPath)
	assert.Error(t, err, "initializing existing database should fail")
	assert.Nil(t, storage2, "storage should be nil when initialization fails")

	t.Logf("InitSQLiteStorage correctly failed with error: %v", err)
}

// TestStorageFileNotExistsError tests that OpenSQLiteStorage fails when file doesn't exist
func TestStorageFileNotExistsError(t *testing.T) {
	// Try to open a non-existent database file
	dbPath := "./non_existent_db.db"

	// Make sure file doesn't exist
	os.Remove(dbPath)

	// Try to open non-existent file (should fail)
	ctx := context.Background()
	storage, err := OpenSQLiteStorage(ctx, dbPath)
	assert.Error(t, err, "opening non-existent database should fail")
	assert.Nil(t, storage, "storage should be nil when open fails")

	t.Logf("OpenSQLiteStorage correctly failed with error: %v", err)
}
