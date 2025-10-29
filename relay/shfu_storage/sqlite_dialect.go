package shfu_storage

import (
	"fmt"
	"time"
)

// SQLiteDialect implements DBDialect for SQLite databases
type SQLiteDialect struct{}

// NewSQLiteDialect creates a new SQLite dialect
func NewSQLiteDialect() *SQLiteDialect {
	return &SQLiteDialect{}
}

// GetCreateTableSQL returns SQLite-specific table creation statements
func (d *SQLiteDialect) GetCreateTableSQL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS shfu_records (
			chain_id TEXT NOT NULL,
			counterparty_chain_id TEXT NOT NULL,
			from_height_revision_number INTEGER NOT NULL,
			from_height_revision_height INTEGER NOT NULL,
			latest_finalized_height_revision_number INTEGER NOT NULL,
			latest_finalized_height_revision_height INTEGER NOT NULL,
			latest_finalized_height_time TEXT NOT NULL, -- SQLite has no native DATETIME type, uses TEXT for dates
			updated_at TEXT NOT NULL, -- SQLite has no native DATETIME type, uses TEXT for dates
			update_client_results BLOB,
			PRIMARY KEY (chain_id, counterparty_chain_id, from_height_revision_number, from_height_revision_height, latest_finalized_height_revision_number, latest_finalized_height_revision_height)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_shfu_records_chain_counterparty 
		 ON shfu_records(chain_id, counterparty_chain_id)`,
		`CREATE INDEX IF NOT EXISTS idx_shfu_records_height 
		 ON shfu_records(from_height_revision_height)`,
		`CREATE INDEX IF NOT EXISTS idx_shfu_records_updated_at 
		 ON shfu_records(updated_at)`,
	}
}

// ConvertTimeToDB converts Go time to SQLite DATETIME format
func (d *SQLiteDialect) ConvertTimeToDB(t time.Time) interface{} {
	// Use SQLite's preferred ISO 8601 format for DATETIME columns
	// This enables proper date/time comparisons and functions
	return t.UTC().Format("2006-01-02 15:04:05")
}

// ConvertTimeFromDB converts SQLite time to Go time
// sqlx automatically converts TEXT datetime to time.Time, so we only handle time.Time
func (d *SQLiteDialect) ConvertTimeFromDB(dbTime interface{}) (time.Time, error) {
	// sqlx automatically converts SQLite datetime TEXT to time.Time
	if t, ok := dbTime.(time.Time); ok {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("expected time.Time from sqlx, got %T", dbTime)
}

// GetPlaceholder returns SQLite placeholder syntax (always "?")
func (d *SQLiteDialect) GetPlaceholder(index int) string {
	return "?"
}
