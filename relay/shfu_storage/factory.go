package shfu_storage

import (
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// InitSQLiteStorage creates a new SQLite database file and initializes the SHFU storage
// Returns error if the database file already exists
func InitSQLiteStorage(dbPath string) (*SqlxSHFUStorage, error) {
	// Check if file already exists
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("database file already exists: %s", dbPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to check database file: %w", err)
	}

	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	dialect := NewSQLiteDialect()
	return NewSqlxSHFUStorage(db, dialect)
}

// OpenSQLiteStorage opens an existing SQLite database file for SHFU storage
// Returns error if the database file does not exist
func OpenSQLiteStorage(dbPath string) (*SqlxSHFUStorage, error) {
	// Check if file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database file does not exist: %s", dbPath)
	} else if err != nil {
		return nil, fmt.Errorf("failed to check database file: %w", err)
	}

	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	dialect := NewSQLiteDialect()
	storage, err := NewSqlxSHFUStorage(db, dialect)
	if err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}
