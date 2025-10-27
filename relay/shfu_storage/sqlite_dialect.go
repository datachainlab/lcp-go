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
			latest_finalized_height_time DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
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

// ConvertTimeToDB converts Go time to SQLite format (string)
func (d *SQLiteDialect) ConvertTimeToDB(t time.Time) interface{} {
	return t.UTC().Format("2006-01-02 15:04:05.000")
}

// ConvertTimeFromDB converts SQLite time string to Go time
func (d *SQLiteDialect) ConvertTimeFromDB(dbTime interface{}) (time.Time, error) {
	timeStr, ok := dbTime.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("expected string for time, got %T", dbTime)
	}

	// Try multiple time formats that SQLite might return
	formats := []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time string: %s", timeStr)
}

// GetPlaceholder returns SQLite placeholder syntax (always "?")
func (d *SQLiteDialect) GetPlaceholder(index int) string {
	return "?"
}
