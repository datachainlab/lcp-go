package storage

import (
	"context"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" // CGO SQLite driver
)

// InitSQLiteStorage creates a new SQLite database file and initializes the ELCUpdate storage
// Returns error if the database file already exists
func InitSQLiteStorage(ctx context.Context, dbPath string) (*SqlxStorage, error) {
	// Check if file already exists
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("database file already exists: %s", dbPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to check database file: %w", err)
	}

	db, err := sqlx.Connect("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	dialect := NewSQLiteDialect()

	storage, err := NewSqlxStorage(db, dialect, dbPath)
	if err != nil {
		db.Close()
		return nil, err
	}
	return storage, nil
}

// OpenSQLiteStorage opens an existing SQLite database file for ELCUpdate storage
// Returns error if the database file does not exist
func OpenSQLiteStorage(ctx context.Context, dbPath string) (*SqlxStorage, error) {
	// Check if file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database file does not exist: %s", dbPath)
	} else if err != nil {
		return nil, fmt.Errorf("failed to check database file: %w", err)
	}

	db, err := sqlx.Connect("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	dialect := NewSQLiteDialect()
	storage, err := NewSqlxStorage(db, dialect, dbPath)
	if err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}
