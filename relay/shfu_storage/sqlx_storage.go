package shfu_storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/jmoiron/sqlx"
)

// errWithStack creates an error with stack trace information
func errWithStack(format string, args ...interface{}) error {
	baseErr := fmt.Errorf(format, args...)
	stack := debug.Stack()
	return fmt.Errorf("%w\nStack trace:\n%s", baseErr, string(stack))
}

// SELECT clause for SHFU records - must match the order in scanSHFURecord
const shfuRecordSelectClause = `
	SELECT chain_id, from_height_revision_number, 
	       from_height_revision_height, to_height_revision_number, 
	       to_height_revision_height, to_height_time, 
	       updated_at, update_client_results
	FROM shfu_records`

/*
DB Schema Overview:

1. shfu_records - Main records table for SHFU (SetupHeadersForUpdate) operations
   - Stores chain information, height data, and execution metadata
   - Primary key: combination of chain_id and height fields
   - Key fields: chain_id, various height revisions
   - Includes error tracking and timestamps

2. shfu_headers - Headers associated with each SHFU record
   - Stores individual header data for each update operation
   - Links to shfu_records via record_id (foreign key)
   - Contains header type, binary data, and processing information
   - Auto-incrementing primary key with proper indexing

Indexes:
   - Chain for efficient filtering
   - Height-based queries for chronological operations
   - Creation time for temporal analysis
   - Record ID for header lookups
*/

// DBDialect defines database-specific operations to abstract SQL differences
type DBDialect interface {
	// GetCreateTableSQL returns the SQL statements to create required tables
	GetCreateTableSQL() []string

	// ConvertTimeToDB converts Go time to database format
	ConvertTimeToDB(t time.Time) interface{}

	// ConvertTimeFromDB converts database time format to Go time
	ConvertTimeFromDB(dbTime interface{}) (time.Time, error)

	// GetPlaceholder returns the placeholder syntax for parameter binding (e.g., "?" for SQLite, "$1" for PostgreSQL)
	GetPlaceholder(index int) string

	// ConfigureDatabase applies database-specific configuration settings
	ConfigureDatabase(db *sqlx.DB) error
}

// SqlxSHFUStorage implements SHFUStorage using sqlx with database abstraction
type SqlxSHFUStorage struct {
	db      *sqlx.DB
	dialect DBDialect
}

// NewSqlxSHFUStorage creates a new sqlx-based SHFU storage
func NewSqlxSHFUStorage(db *sqlx.DB, dialect DBDialect) (*SqlxSHFUStorage, error) {
	storage := &SqlxSHFUStorage{
		db:      db,
		dialect: dialect,
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
func (s *SqlxSHFUStorage) initSchema() error {
	statements := s.dialect.GetCreateTableSQL()
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return errWithStack("failed to execute schema statement: %w", err)
		}
	}
	return nil
}

// SaveSHFUResult saves a SetupHeadersForUpdate execution result
func (s *SqlxSHFUStorage) SaveSHFUResult(ctx context.Context, record *SHFURecord) error {
	// Start transaction for consistency
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return errWithStack("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert the main SHFU record
	if err := s.insertSHFURecord(ctx, tx, record); err != nil {
		return errWithStack("failed to insert SHFU record: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errWithStack("failed to commit transaction: %w", err)
	}

	return nil
}

// ListAllSHFURecords lists all SHFU records in the database
func (s *SqlxSHFUStorage) ListAllSHFURecords(ctx context.Context) ([]*SHFURecord, error) {
	query := shfuRecordSelectClause + `
	       ORDER BY chain_id, from_height_revision_number, from_height_revision_height, 
	                to_height_revision_number, to_height_revision_height`

	rows, err := s.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// FindSHFUByChainAndHeight finds SHFU records for a specific chain and exact height match
func (s *SqlxSHFUStorage) FindSHFUByChainAndHeight(ctx context.Context, chainID string, fromHeight, toHeight ibcexported.Height) ([]*SHFURecord, error) {
	p1, p2, p3, p4, p5 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3), s.dialect.GetPlaceholder(4), s.dialect.GetPlaceholder(5)

	query := fmt.Sprintf(shfuRecordSelectClause+` 
		WHERE chain_id = %s 
		  AND from_height_revision_number = %s 
		  AND from_height_revision_height = %s 
		  AND to_height_revision_number = %s 
		  AND to_height_revision_height = %s
		ORDER BY updated_at DESC
	`, p1, p2, p3, p4, p5)

	rows, err := s.db.QueryxContext(ctx, query, chainID, fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight(), toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight())
	if err != nil {
		return nil, errWithStack("failed to query SHFU records: %w", err)
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, errWithStack("failed to scan SHFU record: %w", err)
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, errWithStack("row iteration error: %w", err)
	}

	return records, nil
}

// GetLatestSHFUForChain retrieves the most recent SHFU record for a chain
func (s *SqlxSHFUStorage) GetLatestSHFUForChain(ctx context.Context, chainID string) (*SHFURecord, error) {
	p1 := s.dialect.GetPlaceholder(1)

	query := fmt.Sprintf(shfuRecordSelectClause+` 
		WHERE chain_id = %s
		ORDER BY to_height_revision_number DESC, to_height_revision_height DESC, from_height_revision_number DESC, from_height_revision_height DESC
		LIMIT 1
	`, p1)

	row := s.db.QueryRowxContext(ctx, query, chainID)

	record, err := s.scanSHFURecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errWithStack("failed to scan latest SHFU record: %w", err)
	}

	return record, nil
}

// FindSHFUByTimeRange finds SHFU records within a time range
func (s *SqlxSHFUStorage) FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error) {
	p1, p2, p3 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3)

	query := fmt.Sprintf(shfuRecordSelectClause+` 
		WHERE chain_id = %s AND updated_at BETWEEN %s AND %s
		ORDER BY updated_at DESC
	`, p1, p2, p3)

	rows, err := s.db.QueryxContext(ctx, query, chainID, s.dialect.ConvertTimeToDB(fromTime), s.dialect.ConvertTimeToDB(toTime))
	if err != nil {
		return nil, errWithStack("failed to query SHFU records by time range: %w", err)
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, errWithStack("failed to scan SHFU record: %w", err)
		}

		records = append(records, record)
	}

	return records, nil
}

// CleanupOldSHFU removes SHFU records older than the specified duration
func (s *SqlxSHFUStorage) CleanupOldSHFU(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)
	p1 := s.dialect.GetPlaceholder(1)

	// Delete records
	recordQuery := fmt.Sprintf(`DELETE FROM shfu_records WHERE created_at < %s`, p1)
	result, err := s.db.ExecContext(ctx, recordQuery, s.dialect.ConvertTimeToDB(cutoffTime))
	if err != nil {
		return 0, errWithStack("failed to delete old SHFU records: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errWithStack("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// Close closes the service and releases any resources
func (s *SqlxSHFUStorage) Close() error {
	return s.db.Close()
}

// Helper methods (implemented below)

func (s *SqlxSHFUStorage) insertSHFURecord(ctx context.Context, tx *sqlx.Tx, record *SHFURecord) error {
	query := `INSERT INTO shfu_records (
		chain_id,
		from_height_revision_number, from_height_revision_height,
		to_height_revision_number, to_height_revision_height,
		to_height_time, updated_at, update_client_results
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	// Serialize UpdateClientResults to JSON
	updateClientResultsJSON, err := json.Marshal(record.UpdateClientResults)
	if err != nil {
		return errWithStack("failed to marshal UpdateClientResults: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		record.ChainID,
		record.FromHeight.RevisionNumber,
		record.FromHeight.RevisionHeight,
		record.ToHeight.RevisionNumber,
		record.ToHeight.RevisionHeight,
		s.dialect.ConvertTimeToDB(record.ToHeightTime),
		s.dialect.ConvertTimeToDB(record.UpdatedAt),
		updateClientResultsJSON,
	)

	return err
}

func (s *SqlxSHFUStorage) scanSHFURecord(scanner sqlx.ColScanner) (*SHFURecord, error) {
	var record SHFURecord
	var updateClientResultsJSON []byte
	var toHeightTimeStr string
	var updatedAtStr string

	err := scanner.Scan(
		&record.ChainID,
		&record.FromHeight.RevisionNumber,
		&record.FromHeight.RevisionHeight,
		&record.ToHeight.RevisionNumber,
		&record.ToHeight.RevisionHeight,
		&toHeightTimeStr,
		&updatedAtStr,
		&updateClientResultsJSON,
	)
	if err != nil {
		return nil, err
	}

	// Convert string timestamps to time.Time using the dialect converter
	record.ToHeightTime, err = s.dialect.ConvertTimeFromDB(toHeightTimeStr)
	if err != nil {
		return nil, errWithStack("failed to convert ToHeightTime: %w", err)
	}

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
