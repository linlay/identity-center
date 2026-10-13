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
	return ensureAccountSessionSchema(db)
}

func ensureAccountSessionSchema(db *sql.DB) error {
	columns, err := tableColumns(db, "DEVICE_")
	if err != nil {
		return err
	}
	if !columns["ACCOUNT_ID_"] {
		if _, err := db.Exec(`ALTER TABLE DEVICE_ ADD COLUMN ACCOUNT_ID_ TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("migrate DEVICE_.ACCOUNT_ID_: %w", err)
		}
	}
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS IDX_DEVICE_ACCOUNT_STATUS_
		ON DEVICE_(ACCOUNT_ID_, STATUS_, UPDATE_AT_ DESC);
		CREATE TABLE IF NOT EXISTS LOGIN_CHALLENGE_ (
			CHALLENGE_ID_ TEXT PRIMARY KEY,
			CLAIM_TOKEN_SHA256_ TEXT NOT NULL,
			TARGET_DEVICE_NAME_ TEXT NOT NULL,
			STATUS_ TEXT NOT NULL,
			ACCOUNT_ID_ TEXT NOT NULL DEFAULT '',
			CONFIRMER_DEVICE_ID_ TEXT NOT NULL DEFAULT '',
			EXPIRES_AT_ TIMESTAMP NOT NULL,
			CONFIRMED_AT_ TIMESTAMP,
			CLAIMED_AT_ TIMESTAMP,
			CREATE_AT_ TIMESTAMP NOT NULL,
			UPDATE_AT_ TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS IDX_LOGIN_CHALLENGE_EXPIRY_
		ON LOGIN_CHALLENGE_(STATUS_, EXPIRES_AT_);
	`)
	return err
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}
