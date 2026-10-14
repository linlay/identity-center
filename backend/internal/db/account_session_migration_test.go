package db

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitEmbeddedSchemaMigratesLegacyDeviceToAccountSessions(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer database.Close()
	if _, err := database.Exec(`
		CREATE TABLE DEVICE_ (
			DEVICE_ID_ TEXT PRIMARY KEY,
			DEVICE_NAME_ TEXT NOT NULL,
			DEVICE_TOKEN_BCRYPT_ TEXT NOT NULL,
			STATUS_ TEXT NOT NULL DEFAULT 'ACTIVE',
			LAST_SEEN_AT_ TIMESTAMP,
			REVOKED_AT_ TIMESTAMP,
			CREATE_AT_ TIMESTAMP NOT NULL,
			UPDATE_AT_ TIMESTAMP NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if err := InitEmbeddedSchema(database); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}

	if err := InitEmbeddedSchema(database); err != nil {
		t.Fatalf("repeat initialization: %v", err)
	}
	columns, err := tableColumns(database, "DEVICE_")
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	for _, name := range []string{"ACCOUNT_ID_"} {
		if !columns[name] {
			t.Errorf("missing migrated column %s", name)
		}
	}
	for _, obsolete := range []string{"DEVICE_KIND_", "TRUST_LEVEL_", "STATE_VERSION_"} {
		if columns[obsolete] {
			t.Errorf("obsolete device column %s", obsolete)
		}
	}
	assertSQLiteObjectExists(t, database, "index", "IDX_DEVICE_ACCOUNT_STATUS_")
}

func assertSQLiteObjectExists(t *testing.T, database *sql.DB, objectType, name string) {
	t.Helper()
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?`, objectType, name).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if count != 1 {
		t.Errorf("%s %s does not exist", objectType, name)
	}
}

func TestFileAndEmbeddedSchemaStayAligned(t *testing.T) {
	raw, err := os.ReadFile("../../schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := embeddedSchemaFS.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), bytes.TrimSpace(embedded)) {
		t.Fatal("shipped file schema differs from embedded schema")
	}
	database, err := Open(filepath.Join(t.TempDir(), "file.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := InitSchema(database, "../../schema.sql"); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(database, "../../schema.sql"); err != nil {
		t.Fatal(err)
	}
	assertSQLiteObjectExists(t, database, "index", "IDX_DEVICE_ACCOUNT_STATUS_")
}

func TestLegacyExternalSchemaCreatesAllAccountAuthTablesAndPreservesData(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "legacy-external.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// Frozen schema from main (ce351b8), before account sessions and email OTP.
	legacy, err := os.ReadFile("testdata/legacy_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(string(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
		INSERT INTO APP_USER_ VALUES('legacy-account', 'alice', 'unchanged-password', 'Alice', 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
		INSERT INTO DEVICE_ VALUES('legacy-device', 'Old Device', 'unchanged-token', 'ACTIVE', NULL, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
	`); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "legacy.sql")
	if err := os.WriteFile(file, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(database, file); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(database, file); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ACCOUNT_EMAIL_", "EMAIL_CHALLENGE_", "EMAIL_LIMIT_", "EMAIL_AUDIT_"} {
		assertSQLiteObjectExists(t, database, "table", name)
	}
	assertSQLiteObjectExists(t, database, "index", "IDX_DEVICE_ACCOUNT_STATUS_")
	var accountID, deviceToken, password string
	if err := database.QueryRow(`SELECT ACCOUNT_ID_, DEVICE_TOKEN_BCRYPT_ FROM DEVICE_ WHERE DEVICE_ID_='legacy-device'`).Scan(&accountID, &deviceToken); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT PASSWORD_BCRYPT_ FROM APP_USER_ WHERE USER_ID_='legacy-account'`).Scan(&password); err != nil {
		t.Fatal(err)
	}
	if accountID != "" || deviceToken != "unchanged-token" || password != "unchanged-password" {
		t.Fatalf("migration changed legacy data: account=%q deviceToken=%q password=%q", accountID, deviceToken, password)
	}
}
