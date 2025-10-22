package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

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

	// Insert associated headers
	for _, header := range record.Headers {
		if err := s.insertSHFUHeader(ctx, tx, record.ID, &header); err != nil {
			return fmt.Errorf("failed to insert SHFU header: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// FindSHFUByChainAndHeight finds SHFU records for a specific chain and counterparty height range
func (s *SqlxSHFUStorage) FindSHFUByChainAndHeight(ctx context.Context, chainID string, counterpartyChainID string, fromHeight, toHeight uint64) ([]*SHFURecord, error) {
	p1, p2, p3, p4 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3), s.dialect.GetPlaceholder(4)

	query := fmt.Sprintf(`
		SELECT id, chain_id, counterparty_chain_id, counterparty_height_revision_number, 
		       counterparty_height_revision_height, latest_height_revision_number, 
		       latest_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, error_message, created_at, 
		       updated_at, metadata
		FROM shfu_records 
		WHERE chain_id = %s AND counterparty_chain_id = %s 
		  AND counterparty_height_revision_height BETWEEN %s AND %s
		ORDER BY created_at DESC
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

		// Load associated headers
		if err := s.loadHeaders(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to load headers for record %s: %w", record.ID, err)
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
		SELECT id, chain_id, counterparty_chain_id, counterparty_height_revision_number, 
		       counterparty_height_revision_height, latest_height_revision_number, 
		       latest_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, error_message, created_at, 
		       updated_at, metadata
		FROM shfu_records 
		WHERE chain_id = %s AND counterparty_chain_id = %s
		ORDER BY created_at DESC 
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

	// Load associated headers
	if err := s.loadHeaders(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to load headers for record %s: %w", record.ID, err)
	}

	return record, nil
}

// FindSHFUByTimeRange finds SHFU records within a time range
func (s *SqlxSHFUStorage) FindSHFUByTimeRange(ctx context.Context, chainID string, fromTime, toTime time.Time) ([]*SHFURecord, error) {
	p1, p2, p3 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2), s.dialect.GetPlaceholder(3)

	query := fmt.Sprintf(`
		SELECT id, chain_id, counterparty_chain_id, counterparty_height_revision_number, 
		       counterparty_height_revision_height, latest_height_revision_number, 
		       latest_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, error_message, created_at, 
		       updated_at, metadata
		FROM shfu_records 
		WHERE chain_id = %s AND created_at BETWEEN %s AND %s
		ORDER BY created_at DESC
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

		// Load associated headers
		if err := s.loadHeaders(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to load headers for record %s: %w", record.ID, err)
		}

		records = append(records, record)
	}

	return records, nil
}

// FindFailedSHFU finds failed SHFU operations for retry or analysis
func (s *SqlxSHFUStorage) FindFailedSHFU(ctx context.Context, chainID string, limit int) ([]*SHFURecord, error) {
	p1, p2 := s.dialect.GetPlaceholder(1), s.dialect.GetPlaceholder(2)

	query := fmt.Sprintf(`
		SELECT id, chain_id, counterparty_chain_id, counterparty_height_revision_number, 
		       counterparty_height_revision_height, latest_height_revision_number, 
		       latest_height_revision_height, latest_finalized_height_revision_number, 
		       latest_finalized_height_revision_height, error_message, created_at, 
		       updated_at, metadata
		FROM shfu_records 
		WHERE chain_id = %s AND error_message IS NOT NULL AND error_message != ''
		ORDER BY created_at DESC 
		LIMIT %s
	`, p1, p2)

	rows, err := s.db.QueryxContext(ctx, query, chainID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed SHFU records: %w", err)
	}
	defer rows.Close()

	var records []*SHFURecord
	for rows.Next() {
		record, err := s.scanSHFURecord(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SHFU record: %w", err)
		}

		// Load associated headers
		if err := s.loadHeaders(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to load headers for record %s: %w", record.ID, err)
		}

		records = append(records, record)
	}

	return records, nil
}

// CleanupOldSHFU removes SHFU records older than the specified duration
func (s *SqlxSHFUStorage) CleanupOldSHFU(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)
	p1 := s.dialect.GetPlaceholder(1)

	// Delete headers first (foreign key constraint)
	headerQuery := fmt.Sprintf(`
		DELETE FROM shfu_headers 
		WHERE record_id IN (
			SELECT id FROM shfu_records WHERE created_at < %s
		)
	`, p1)

	_, err := s.db.ExecContext(ctx, headerQuery, s.dialect.ConvertTimeToDB(cutoffTime))
	if err != nil {
		return 0, fmt.Errorf("failed to delete old SHFU headers: %w", err)
	}

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
	// Serialize metadata to JSON
	var metadataJSON sql.NullString
	if record.Metadata != nil {
		jsonBytes, err := json.Marshal(record.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = sql.NullString{String: string(jsonBytes), Valid: true}
	}

	query := `INSERT INTO shfu_records (
		id, chain_id, counterparty_chain_id,
		counterparty_height_revision_number, counterparty_height_revision_height,
		latest_height_revision_number, latest_height_revision_height,
		latest_finalized_height_revision_number, latest_finalized_height_revision_height,
		error_message, created_at, updated_at, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := tx.ExecContext(ctx, query,
		record.ID,
		record.ChainID,
		record.CounterpartyChainID,
		record.CounterpartyHeight.RevisionNumber,
		record.CounterpartyHeight.RevisionHeight,
		record.LatestHeight.RevisionNumber,
		record.LatestHeight.RevisionHeight,
		record.LatestFinalizedHeight.RevisionNumber,
		record.LatestFinalizedHeight.RevisionHeight,
		record.ErrorMessage,
		s.dialect.ConvertTimeToDB(record.CreatedAt),
		s.dialect.ConvertTimeToDB(record.UpdatedAt),
		metadataJSON,
	)

	return err
}

func (s *SqlxSHFUStorage) insertSHFUHeader(ctx context.Context, tx *sqlx.Tx, recordID string, header *SHFUHeaderRecord) error {
	query := `INSERT INTO shfu_headers (
		record_id, header_index, height_revision_number, height_revision_height,
		header_type, header_data, processed_at, error_message
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := tx.ExecContext(ctx, query,
		recordID,
		header.Index,
		header.Height.RevisionNumber,
		header.Height.RevisionHeight,
		header.HeaderType,
		header.HeaderData,
		s.dialect.ConvertTimeToDB(header.ProcessedAt),
		header.ErrorMessage,
	)

	return err
}

func (s *SqlxSHFUStorage) scanSHFURecord(scanner rowScanner) (*SHFURecord, error) {
	var record SHFURecord
	var metadataJSON sql.NullString
	var createdAtDB, updatedAtDB interface{}

	err := scanner.Scan(
		&record.ID,
		&record.ChainID,
		&record.CounterpartyChainID,
		&record.CounterpartyHeight.RevisionNumber,
		&record.CounterpartyHeight.RevisionHeight,
		&record.LatestHeight.RevisionNumber,
		&record.LatestHeight.RevisionHeight,
		&record.LatestFinalizedHeight.RevisionNumber,
		&record.LatestFinalizedHeight.RevisionHeight,
		&record.ErrorMessage,
		&createdAtDB,
		&updatedAtDB,
		&metadataJSON,
	)
	if err != nil {
		return nil, err
	}

	// Parse timestamps
	record.CreatedAt, err = s.dialect.ConvertTimeFromDB(createdAtDB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	record.UpdatedAt, err = s.dialect.ConvertTimeFromDB(updatedAtDB)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	// Parse metadata JSON
	if metadataJSON.Valid {
		if err := json.Unmarshal([]byte(metadataJSON.String), &record.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &record, nil
}

func (s *SqlxSHFUStorage) loadHeaders(ctx context.Context, record *SHFURecord) error {
	query := `SELECT header_index, height_revision_number, height_revision_height,
	                 header_type, header_data, processed_at, error_message
	          FROM shfu_headers 
	          WHERE record_id = ? 
	          ORDER BY header_index`

	rows, err := s.db.QueryxContext(ctx, query, record.ID)
	if err != nil {
		return fmt.Errorf("failed to query headers: %w", err)
	}
	defer rows.Close()

	var headers []SHFUHeaderRecord
	for rows.Next() {
		var header SHFUHeaderRecord
		var processedAtDB interface{}

		err := rows.Scan(
			&header.Index,
			&header.Height.RevisionNumber,
			&header.Height.RevisionHeight,
			&header.HeaderType,
			&header.HeaderData,
			&processedAtDB,
			&header.ErrorMessage,
		)
		if err != nil {
			return fmt.Errorf("failed to scan header: %w", err)
		}

		// Parse timestamp
		header.ProcessedAt, err = s.dialect.ConvertTimeFromDB(processedAtDB)
		if err != nil {
			return fmt.Errorf("failed to parse processed_at: %w", err)
		}

		headers = append(headers, header)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %w", err)
	}

	record.Headers = headers
	return nil
}
