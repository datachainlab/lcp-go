// Package storage provides SQLite-based storage for updateClient operations.
//
// Temporary Error Handling:
// The storage implementation provides IsTemporaryError() to detect database locking,
// connection issues, and other retryable errors.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/elcupdater/log"
	"github.com/jmoiron/sqlx"
)

// errWithStack creates an error with stack trace information
func errWithStack(format string, args ...interface{}) error {
	baseErr := fmt.Errorf(format, args...)
	stack := debug.Stack()
	return fmt.Errorf("%w\nStack trace:\n%s", baseErr, string(stack))
}

// SELECT clause for records - must match the order in scan
const selectClause = `
	SELECT chain_id, counterparty_chain_id, from_height_revision_number, 
	       from_height_revision_height, to_height_revision_number, 
	       to_height_revision_height, updated_at, 
	       update_client_results, latest_finalized_header
	FROM records`

/*
DB Schema Overview:

1. records - Main records table for ELCUpdate (updateClient) operations
   - Stores chain information, height data, and execution metadata
   - Primary key: combination of chain_id, counterparty_chain_id, from_height fields, and to_height fields
   - Key fields: chain_id, counterparty_chain_id, from_height_revision_number, from_height_revision_height, to_height_revision_number, to_height_revision_height
   - Includes timestamp (updated_at), serialized update_client_results, and latest_finalized_header

Indexes:
   - Chain ID for efficient filtering by chain
   - Height-based queries for chronological operations
   - Updated timestamp for temporal analysis and cleanup operations
*/

// DBDialect defines database-specific operations to abstract SQL differences
type DBDialect interface {
	// GetCreateTableSQL returns the SQL statements to create required tables
	GetCreateTableSQL() []string

	// ConvertTimeToDB converts Go time to database format
	ConvertTimeToDB(t time.Time) interface{}

	// ConvertTimeFromDB converts database time format to Go time
	ConvertTimeFromDB(dbTime interface{}) (time.Time, error)

	// ConfigureDatabase applies database-specific configuration settings
	ConfigureDatabase(db *sqlx.DB) error
}

// SqlxStorage implements Storage using sqlx with database abstraction
type SqlxStorage struct {
	db       *sqlx.DB
	dialect  DBDialect
	filePath string // SQLite database file path
}

// NewSqlxStorage creates a new sqlx-based storage
func NewSqlxStorage(db *sqlx.DB, dialect DBDialect, filePath string) (*SqlxStorage, error) {
	storage := &SqlxStorage{
		db:       db,
		dialect:  dialect,
		filePath: filePath,
	}

	// Apply database-specific configuration
	if err := dialect.ConfigureDatabase(db); err != nil {
		return nil, errWithStack("failed to configure database: %w", err)
	}

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		return nil, errWithStack("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the required tables
func (s *SqlxStorage) initSchema() error {
	statements := s.dialect.GetCreateTableSQL()
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return errWithStack("failed to execute schema statement: %w", err)
		}
	}
	return nil
}

// Save saves a updateClient execution result
func (s *SqlxStorage) Save(ctx context.Context, record *Record) error {
	// Get logger from context
	logger := log.GetLogger(ctx)

	// Log transaction start
	logger.InfoContext(ctx, "Starting Save transaction",
		"chain_id", record.ChainID,
		"counterparty_chain_id", record.CounterpartyChainID)

	if err := s.insert(ctx, record); err != nil {
		return errWithStack("failed to insert record: %w", err)
	}

	// Log transaction completion
	logger.InfoContext(ctx, "Completed Save transaction",
		"chain_id", record.ChainID,
		"counterparty_chain_id", record.CounterpartyChainID)

	return nil
}

// List lists Records in the database with optional chain ID filters
func (s *SqlxStorage) List(ctx context.Context, chainID, counterpartyChainID string) ([]*Record, error) {
	var whereConditions []string
	namedArgs := map[string]interface{}{}

	// Add WHERE conditions if filters are provided
	if chainID != "" {
		whereConditions = append(whereConditions, "chain_id = :chain_id")
		namedArgs["chain_id"] = chainID
	}
	if counterpartyChainID != "" {
		whereConditions = append(whereConditions, "counterparty_chain_id = :counterparty_chain_id")
		namedArgs["counterparty_chain_id"] = counterpartyChainID
	}

	// Build the query
	query := selectClause
	if len(whereConditions) > 0 {
		query += " WHERE " + strings.Join(whereConditions, " AND ")
	}
	query += " ORDER BY chain_id, to_height_revision_number, to_height_revision_height"

	// Execute query with named parameters
	rows, err := s.db.NamedQueryContext(ctx, query, namedArgs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		record, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// FindByChainAndHeight finds records for a specific chain and exact height match
func (s *SqlxStorage) FindByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight ibcexported.Height, toHeight ibcexported.Height) ([]*Record, error) {
	query := selectClause + `
		WHERE chain_id = :chain_id
		  AND from_height_revision_number = :from_rev_num
		  AND from_height_revision_height = :from_rev_height
		  AND to_height_revision_number = :to_rev_num
		  AND to_height_revision_height = :to_rev_height
	`
	if counterpartyChainID != "" {
		query += " AND counterparty_chain_id = :counterparty_chain_id"
	}
	query += " ORDER BY updated_at DESC"

	namedArgs := map[string]interface{}{
		"chain_id":              chainID,
		"counterparty_chain_id": counterpartyChainID,
		"from_rev_num":          fromHeight.GetRevisionNumber(),
		"from_rev_height":       fromHeight.GetRevisionHeight(),
		"to_rev_num":            toHeight.GetRevisionNumber(),
		"to_rev_height":         toHeight.GetRevisionHeight(),
	}

	rows, err := s.db.NamedQueryContext(ctx, query, namedArgs)
	if err != nil {
		counterpartyStr := counterpartyChainID
		if counterpartyStr == "" {
			counterpartyStr = "any"
		}
		return nil, errWithStack("failed to query records (chain=%s, counterparty=%s, fromHeight=%d-%d, toHeight=%d-%d): %w",
			chainID, counterpartyStr,
			fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight(),
			toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight(), err)
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		record, err := s.scan(rows)
		if err != nil {
			return nil, errWithStack("failed to scan record: %w", err)
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, errWithStack("row iteration error: %w", err)
	}

	return records, nil
}

// GetLatestForChain retrieves the most recent Record for a chain
// If counterpartyChainID is empty, it will be ignored in the query
func (s *SqlxStorage) GetLatestForChain(ctx context.Context, chainID string, counterpartyChainID string) (*Record, error) {
	query := selectClause + `
		WHERE chain_id = :chain_id
	`
	if counterpartyChainID != "" {
		query += " AND counterparty_chain_id = :counterparty_chain_id"
	}
	query += `
		ORDER BY to_height_revision_number DESC, to_height_revision_height DESC
		LIMIT 1
	`

	namedArgs := map[string]interface{}{
		"chain_id":              chainID,
		"counterparty_chain_id": counterpartyChainID,
	}

	rows, err := s.db.NamedQueryContext(ctx, query, namedArgs)
	if err != nil {
		return nil, errWithStack("failed to query latest Record: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, nil
	}

	record, err := s.scan(rows)
	if err != nil {
		return nil, errWithStack("failed to scan latest Record: %w", err)
	}

	return record, nil
}

// GetSequence retrieves sequential records starting from the specified height
// If toHeight is not nil, stops when reaching a record with that ToHeight
func (s *SqlxStorage) GetSequence(ctx context.Context, chainID string, counterpartyChainID string, fromHeight ibcexported.Height, toHeight ibcexported.Height) ([]*Record, error) {
	// Step 1: Get all records with fromHeight >= specified fromHeight
	query := selectClause + `
		WHERE chain_id = :chain_id
	`
	if counterpartyChainID != "" {
		query += " AND counterparty_chain_id = :counterparty_chain_id"
	}
	query += `
		AND (from_height_revision_number = :from_rev_num AND from_height_revision_height >= :from_rev_height)
	`

	namedArgs := map[string]interface{}{
		"chain_id":              chainID,
		"counterparty_chain_id": counterpartyChainID,
		"from_rev_num":          fromHeight.GetRevisionNumber(),
		"from_rev_height":       fromHeight.GetRevisionHeight(),
	}

	if toHeight != nil {
		query += `
			AND (to_height_revision_number = :to_rev_num AND to_height_revision_height <= :to_rev_height)
		`
		namedArgs["to_rev_num"] = toHeight.GetRevisionNumber()
		namedArgs["to_rev_height"] = toHeight.GetRevisionHeight()
	}

	query += ` ORDER BY from_height_revision_number, from_height_revision_height`

	rows, err := s.db.NamedQueryContext(ctx, query, namedArgs)
	if err != nil {
		counterpartyStr := counterpartyChainID
		if counterpartyStr == "" {
			counterpartyStr = "any"
		}
		return nil, errWithStack("failed to query sequential records (chain=%s, counterparty=%s, fromHeight=%d-%d): %w",
			chainID, counterpartyStr,
			fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight(), err)
	}
	defer rows.Close()

	// Build map: fromHeight -> []*Record
	recordMap := make(map[string][]*Record)
	for rows.Next() {
		record, err := s.scan(rows)
		if err != nil {
			return nil, errWithStack("failed to scan record: %w", err)
		}

		fromKey := fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight)
		recordMap[fromKey] = append(recordMap[fromKey], record)
	}

	if err := rows.Err(); err != nil {
		return nil, errWithStack("error iterating rows: %w", err)
	}

	// Step 2-3: Build sequential chain starting from fromHeight
	var result []*Record
	currentHeight := fromHeight

	for {
		currentKey := fmt.Sprintf("%d-%d", currentHeight.GetRevisionNumber(), currentHeight.GetRevisionHeight())
		records, exists := recordMap[currentKey]
		if !exists || len(records) == 0 {
			// No records found for current height, end the chain
			break
		}

		// Find the record with the highest toHeight
		var selectedRecord *Record
		for _, record := range records {
			if selectedRecord == nil {
				selectedRecord = record
				continue
			}

			// Compare toHeight: select the one with higher height
			if record.ToHeight.RevisionNumber > selectedRecord.ToHeight.RevisionNumber ||
				(record.ToHeight.RevisionNumber == selectedRecord.ToHeight.RevisionNumber &&
					record.ToHeight.RevisionHeight > selectedRecord.ToHeight.RevisionHeight) {
				selectedRecord = record
			}
		}

		// Add selected record to result
		result = append(result, selectedRecord)

		// If toHeight is specified and this record reaches it, stop here
		if toHeight != nil {
			if selectedRecord.ToHeight.RevisionNumber == toHeight.GetRevisionNumber() &&
				selectedRecord.ToHeight.RevisionHeight == toHeight.GetRevisionHeight() {
				// Reached target toHeight, stop the chain
				break
			}
		}

		// Update currentHeight to selected record's toHeight for next iteration
		currentHeight = clienttypes.NewHeight(selectedRecord.ToHeight.RevisionNumber, selectedRecord.ToHeight.RevisionHeight)
	}

	return result, nil
}

// Cleanup removes records older than the specified duration based on UpdatedAt
func (s *SqlxStorage) Cleanup(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)

	// Delete records based on updated_at
	recordQuery := `DELETE FROM records WHERE updated_at < :cutoff_time`
	namedArgs := map[string]interface{}{
		"cutoff_time": s.dialect.ConvertTimeToDB(cutoffTime),
	}

	result, err := s.db.NamedExecContext(ctx, recordQuery, namedArgs)
	if err != nil {
		return 0, errWithStack("failed to delete old records: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errWithStack("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// Close closes the service and releases any resources
func (s *SqlxStorage) Close() error {
	return s.db.Close()
}

// Helper methods (implemented below)

func (s *SqlxStorage) insert(ctx context.Context, record *Record) error {
	query := `INSERT INTO records (
		chain_id, counterparty_chain_id,
		from_height_revision_number, from_height_revision_height,
		to_height_revision_number, to_height_revision_height,
		updated_at, update_client_results, latest_finalized_header
	) VALUES (
		:chain_id, :counterparty_chain_id,
		:from_height_revision_number, :from_height_revision_height,
		:to_height_revision_number, :to_height_revision_height,
		:updated_at, :update_client_results, :latest_finalized_header
	)`

	// Serialize UpdateClientResults to JSON
	updateClientResultsJSON, err := json.Marshal(record.UpdateClientResults)
	if err != nil {
		return errWithStack("failed to marshal UpdateClientResults: %w", err)
	}

	namedArgs := map[string]interface{}{
		"chain_id":                    record.ChainID,
		"counterparty_chain_id":       record.CounterpartyChainID,
		"from_height_revision_number": record.FromHeight.RevisionNumber,
		"from_height_revision_height": record.FromHeight.RevisionHeight,
		"to_height_revision_number":   record.ToHeight.RevisionNumber,
		"to_height_revision_height":   record.ToHeight.RevisionHeight,
		"updated_at":                  s.dialect.ConvertTimeToDB(record.UpdatedAt),
		"update_client_results":       updateClientResultsJSON,
		"latest_finalized_header":     record.LatestFinalizedHeader,
	}

	_, err = s.db.NamedExecContext(ctx, query, namedArgs)

	return err
}

func (s *SqlxStorage) scan(scanner sqlx.ColScanner) (*Record, error) {
	var record Record
	var updateClientResultsJSON []byte
	var updatedAtStr string

	err := scanner.Scan(
		&record.ChainID,
		&record.CounterpartyChainID,
		&record.FromHeight.RevisionNumber,
		&record.FromHeight.RevisionHeight,
		&record.ToHeight.RevisionNumber,
		&record.ToHeight.RevisionHeight,
		&updatedAtStr,
		&updateClientResultsJSON,
		&record.LatestFinalizedHeader,
	)
	if err != nil {
		return nil, err
	}

	// Convert string timestamp to time.Time using the dialect converter
	record.UpdatedAt, err = s.dialect.ConvertTimeFromDB(updatedAtStr)
	if err != nil {
		return nil, errWithStack("failed to convert UpdatedAt: %w", err)
	}

	// Deserialize UpdateClientResults from JSON
	if updateClientResultsJSON != nil {
		err = json.Unmarshal(updateClientResultsJSON, &record.UpdateClientResults)
		if err != nil {
			return nil, errWithStack("failed to unmarshal UpdateClientResults: %w", err)
		}
	}

	return &record, nil
}

// IsTemporaryError determines if an error is temporary and the operation can be retried
// For SQLite, this includes database locks, busy errors, and connection issues
func (s *SqlxStorage) IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// SQLite specific temporary errors
	// SQLITE_BUSY (5): The database file is locked
	// SQLITE_LOCKED (6): A table in the database is locked
	// SQLITE_PROTOCOL (15): Database lock protocol error
	if strings.Contains(errStr, "database is locked") ||
		strings.Contains(errStr, "database table is locked") ||
		strings.Contains(errStr, "SQLITE_BUSY") ||
		strings.Contains(errStr, "SQLITE_LOCKED") ||
		strings.Contains(errStr, "SQLITE_PROTOCOL") {
		return true
	}

	// Connection related errors that might be temporary
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection timeout") ||
		strings.Contains(errStr, "network is unreachable") {
		return true
	}

	// Context timeout errors (might be retryable)
	if strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "context canceled") {
		return true
	}

	return false
}

// Description returns a description of this storage instance
func (s *SqlxStorage) Description() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return fmt.Sprintf("SQLite@%s:%s", hostname, s.filePath)
}
