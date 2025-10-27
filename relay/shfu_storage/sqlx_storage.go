package shfu_storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

/*
DB Schema Overview:

1. shfu_records - Main records table for SHFU (SetupHeadersForUpdate) operations
   - Stores chain information, counterparty details, height data, and execution metadata
   - Primary key: id (TEXT)
   - Key fields: chain_id, counterparty_chain_id, various height revisions
   - Includes error tracking and timestamps

2. shfu_headers - Headers associated with each SHFU record
   - Stores individual header data for each update operation
   - Links to shfu_records via record_id (foreign key)
   - Contains header type, binary data, and processing information
   - Auto-incrementing primary key with proper indexing

Indexes:
   - Chain/counterparty combination for efficient filtering
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

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the required tables
func (s *SqlxSHFUStorage) initSchema() error {
	statements := s.dialect.GetCreateTableSQL()
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %w", err)
		}
	}
	return nil
}

// SaveSHFUResult saves a SetupHeadersForUpdate execution result
func (s *SqlxSHFUStorage) SaveSHFUResult(ctx context.Context, record *SHFURecord) error {
	// Start transaction for consistency
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert the main SHFU record
	if err := s.insertSHFURecord(ctx, tx, record); err != nil {
		return fmt.Errorf("failed to insert SHFU record: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListAllSHFURecords lists all SHFU records in the database
func (s *SqlxSHFUStorage) ListAllSHFURecords(ctx context.Context) ([]*SHFURecord, error) {
	query := `
	       SELECT chain_id, counterparty_chain_id, from_height_revision_number, 
		      from_height_revision_height, latest_finalized_height_revision_number, 
		      latest_finalized_height_revision_height, latest_finalized_height_time, 
		      updated_at, update_client_results
	       FROM shfu_records
	       ORDER BY updated_at DESC`

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

// FindSHFUByChainAndHeight finds SHFU records for a specific chain and from height range
func (s *SqlxSHFUStorage) FindSHFUByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight, toHeight uint64) ([]*SHFURecord, error) {
	p1, p2, p3, p4 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3), s.dialect.GetPlaceholder(4)

	query := fmt.Sprintf(`
		SELECT chain_id, counterparty_chain_id, from_height_revision_number, 
		       from_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, latest_finalized_height_time, 
		       updated_at, update_client_results
		FROM shfu_records 
		WHERE chain_id = %s AND counterparty_chain_id = %s 
		  AND from_height_revision_height BETWEEN %s AND %s
		ORDER BY updated_at DESC
	`, p1, p2, p3, p4)

	rows, err := s.db.QueryxContext(ctx, query, chainID, counterpartyChainID, fromHeight, toHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to query SHFU records: %w", err)
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SHFU record: %w", err)
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return records, nil
}

// GetLatestSHFUForChainPair retrieves the most recent SHFU record for a chain pair
func (s *SqlxSHFUStorage) GetLatestSHFUForChainPair(ctx context.Context, chainID string, counterpartyChainID string) (*SHFURecord, error) {
	p1, p2 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2)

	query := fmt.Sprintf(`
		SELECT chain_id, counterparty_chain_id, from_height_revision_number, 
		       from_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, latest_finalized_height_time, 
		       updated_at, update_client_results
		FROM shfu_records 
		WHERE chain_id = %s AND counterparty_chain_id = %s
		ORDER BY updated_at DESC 
		LIMIT 1
	`, p1, p2)

	row := s.db.QueryRowxContext(ctx, query, chainID, counterpartyChainID)

	record, err := s.scanSHFURecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan latest SHFU record: %w", err)
	}

	return record, nil
}

// FindSHFUByTimeRange finds SHFU records within a time range
func (s *SqlxSHFUStorage) FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error) {
	p1, p2, p3 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3)

	query := fmt.Sprintf(`
		SELECT chain_id, counterparty_chain_id, from_height_revision_number, 
		       from_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, latest_finalized_height_time, 
		       updated_at, update_client_results
		FROM shfu_records 
		WHERE chain_id = %s AND updated_at BETWEEN %s AND %s
		ORDER BY updated_at DESC
	`, p1, p2, p3)

	rows, err := s.db.QueryxContext(ctx, query, chainID, s.dialect.ConvertTimeToDB(fromTime), s.dialect.ConvertTimeToDB(toTime))
	if err != nil {
		return nil, fmt.Errorf("failed to query SHFU records by time range: %w", err)
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SHFU record: %w", err)
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
		return 0, fmt.Errorf("failed to delete old SHFU records: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// Close closes the service and releases any resources
func (s *SqlxSHFUStorage) Close() error {
	return s.db.Close()
}

// Helper methods (implemented below)

// rowScanner interface for both sql.Row and sqlx.Rows
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (s *SqlxSHFUStorage) insertSHFURecord(ctx context.Context, tx *sqlx.Tx, record *SHFURecord) error {
	query := `INSERT INTO shfu_records (
		chain_id, counterparty_chain_id,
		from_height_revision_number, from_height_revision_height,
		latest_finalized_height_revision_number, latest_finalized_height_revision_height,
		latest_finalized_height_time, updated_at, update_client_results
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// Serialize UpdateClientResults to JSON
	updateClientResultsJSON, err := json.Marshal(record.UpdateClientResults)
	if err != nil {
		return fmt.Errorf("failed to marshal UpdateClientResults: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		record.ChainID,
		record.CounterpartyChainID,
		record.FromHeight.RevisionNumber,
		record.FromHeight.RevisionHeight,
		record.LatestFinalizedHeight.RevisionNumber,
		record.LatestFinalizedHeight.RevisionHeight,
		s.dialect.ConvertTimeToDB(record.LatestFinalizedHeightTime),
		s.dialect.ConvertTimeToDB(record.UpdatedAt),
		updateClientResultsJSON,
	)

	return err
}

func (s *SqlxSHFUStorage) scanSHFURecord(scanner rowScanner) (*SHFURecord, error) {
	var record SHFURecord
	var updatedAtDB, latestFinalizedHeightTimeDB interface{}
	var updateClientResultsJSON []byte

	err := scanner.Scan(
		&record.ChainID,
		&record.CounterpartyChainID,
		&record.FromHeight.RevisionNumber,
		&record.FromHeight.RevisionHeight,
		&record.LatestFinalizedHeight.RevisionNumber,
		&record.LatestFinalizedHeight.RevisionHeight,
		&latestFinalizedHeightTimeDB,
		&updatedAtDB,
		&updateClientResultsJSON,
	)
	if err != nil {
		return nil, err
	}

	// Parse timestamps
	record.UpdatedAt, err = s.dialect.ConvertTimeFromDB(updatedAtDB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	record.LatestFinalizedHeightTime, err = s.dialect.ConvertTimeFromDB(latestFinalizedHeightTimeDB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse latest_finalized_height_time: %w", err)
	}

	// Deserialize UpdateClientResults from JSON
	if updateClientResultsJSON != nil {
		err = json.Unmarshal(updateClientResultsJSON, &record.UpdateClientResults)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal UpdateClientResults: %w", err)
		}
	}

	return &record, nil
}
