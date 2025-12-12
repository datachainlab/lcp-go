package shfu_storage

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
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
			to_height_revision_number INTEGER NOT NULL,
			to_height_revision_height INTEGER NOT NULL,
			to_height_time TEXT NOT NULL, -- SQLite has no native DATETIME type, uses TEXT for dates
			updated_at TEXT NOT NULL, -- SQLite has no native DATETIME type, uses TEXT for dates
			update_client_results BLOB,
			latest_finalized_header BLOB, -- Serialized core.Header bytes
			PRIMARY KEY (chain_id, counterparty_chain_id, from_height_revision_number, from_height_revision_height, to_height_revision_number, to_height_revision_height)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_shfu_records_chain 
		 ON shfu_records(chain_id)`,
		`CREATE INDEX IF NOT EXISTS idx_shfu_records_height 
		 ON shfu_records(to_height_revision_height)`,
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
// Handles both string format (when manually scanning) and time.Time (if sqlx auto-converts)
func (d *SQLiteDialect) ConvertTimeFromDB(dbTime interface{}) (time.Time, error) {
	switch v := dbTime.(type) {
	case time.Time:
		// Already converted by sqlx
		return v.UTC(), nil
	case string:
		// Parse ISO 8601 format string manually
		if v == "" {
			return time.Time{}, nil
		}
		// Try parsing with different layouts
		layouts := []string{
			"2006-01-02 15:04:05",      // SQLite default format
			"2006-01-02T15:04:05Z",     // ISO 8601 with Z
			"2006-01-02T15:04:05",      // ISO 8601 without timezone
			"2006-01-02T15:04:05.000Z", // ISO 8601 with milliseconds
			time.RFC3339,               // Full RFC3339
		}

		for _, layout := range layouts {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("cannot parse time string: %s", v)
	case []byte:
		// Handle byte slice (some drivers might return this)
		return d.ConvertTimeFromDB(string(v))
	default:
		return time.Time{}, fmt.Errorf("expected time.Time or string from DB, got %T", dbTime)
	}
}

// GetPlaceholder returns SQLite placeholder syntax (always "?")
func (d *SQLiteDialect) GetPlaceholder(index int) string {
	return "?"
}

// ConfigureDatabase applies SQLite-specific configuration settings
func (d *SQLiteDialect) ConfigureDatabase(db *sqlx.DB) error {
	// Set SQLite busy timeout for lock handling (30 seconds)
	if _, err := db.Exec("PRAGMA busy_timeout = 30000"); err != nil {
		return fmt.Errorf("failed to set busy timeout: %w", err)
	}

	// Set journal mode to WAL for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("failed to set journal mode: %w", err)
	}

	// Enable foreign key constraints
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Set synchronous to NORMAL for better performance while maintaining safety
	if _, err := db.Exec("PRAGMA synchronous = NORMAL"); err != nil {
		return fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	// Verify settings were applied correctly
	var busyTimeout int
	if err := db.Get(&busyTimeout, "PRAGMA busy_timeout"); err != nil {
		return fmt.Errorf("failed to verify busy timeout: %w", err)
	}
	if busyTimeout != 30000 {
		return fmt.Errorf("busy timeout not set correctly: expected 30000, got %d", busyTimeout)
	}

	var journalMode string
	if err := db.Get(&journalMode, "PRAGMA journal_mode"); err != nil {
		return fmt.Errorf("failed to verify journal mode: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("journal mode not set correctly: expected 'wal', got '%s'", journalMode)
	}

	return nil
}
