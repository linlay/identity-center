package db

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceTTLMigrationPreservesLegacyCredential(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := embeddedSchemaFS.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.ReplaceAll(string(raw), "    MAX_ACCESS_TTL_SECONDS_ INTEGER CHECK (MAX_ACCESS_TTL_SECONDS_ > 0),\n", "")
	if _, err := conn.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO DEVICE_ VALUES ('legacy','original','unchanged-hash','ACTIVE',NULL,NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := InitEmbeddedSchema(conn); err != nil {
			t.Fatal(err)
		}
	}
	var hash, status string
	var limit *int
	if err := conn.QueryRow(`SELECT DEVICE_TOKEN_BCRYPT_,STATUS_,MAX_ACCESS_TTL_SECONDS_ FROM DEVICE_ WHERE DEVICE_ID_='legacy'`).Scan(&hash, &status, &limit); err != nil {
		t.Fatal(err)
	}
	if hash != "unchanged-hash" || status != "ACTIVE" || limit != nil {
		t.Fatal("legacy state changed")
	}
	if _, err := conn.Exec(`UPDATE DEVICE_ SET MAX_ACCESS_TTL_SECONDS_=0 WHERE DEVICE_ID_='legacy'`); err == nil {
		t.Fatal("nonpositive stored limit accepted")
	}
}
