package storage

import (
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// NewSQLiteStorage creates a new SQLite-based SHFU storage
func NewSQLiteStorage(dbPath string) (*SqlxSHFUStorage, error) {
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	dialect := NewSQLiteDialect()
	return NewSqlxSHFUStorage(db, dialect)
}
