package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var embeddedSchemaFS embed.FS

func Open(dbPath string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, err
	}
	return db, nil
}

func InitSchema(db *sql.DB, schemaPath string) error {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	return initSchemaSQL(db, raw)
}

func InitEmbeddedSchema(db *sql.DB) error {
	raw, err := embeddedSchemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	return initSchemaSQL(db, raw)
}

func initSchemaSQL(db *sql.DB, raw []byte) error {
	if _, err := db.Exec(string(raw)); err != nil {
		return err
	}
	// CREATE TABLE IF NOT EXISTS leaves legacy DEVICE_ tables unchanged.
	// Add only the nullable policy column; existing devices keep their policy.
	rows, err := db.Query(`PRAGMA table_info(DEVICE_)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&id, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "MAX_ACCESS_TTL_SECONDS_" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		_, err = db.Exec(`ALTER TABLE DEVICE_ ADD COLUMN MAX_ACCESS_TTL_SECONDS_ INTEGER CHECK (MAX_ACCESS_TTL_SECONDS_ > 0)`)
	}
	return err
}
