package programcli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-center/backend/internal/db"
)

func TestSetupPublicKeyAndIssueTokens(t *testing.T) {
	t.Setenv("DESKTOP_DEVICE_ID", "")
	root := t.TempDir()
	dbPath := filepath.Join(root, "auth.db")
	keyDir := filepath.Join(root, "keys")
	publicOut := filepath.Join(keyDir, "publicKey.pem")

	var stdout, stderr bytes.Buffer
	handled, err := Run([]string{
		"setup-public-key",
		"--db", dbPath,
		"--out", keyDir,
		"--public-out", publicOut,
		"--key-id", "test-kid-1",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("setup-public-key failed: %v stderr=%s", err, stderr.String())
	}
	if !handled {
		t.Fatal("setup-public-key was not handled")
	}
	if !strings.Contains(stdout.String(), "kid=test-kid-1") {
		t.Fatalf("unexpected setup output: %s", stdout.String())
	}
	for _, name := range []string{"jwk-public.pem", "jwk-private.pem", "publicKey.pem"} {
		if !fileExists(filepath.Join(keyDir, name)) {
			t.Fatalf("expected key file %s", name)
		}
	}

	stdout.Reset()
	stderr.Reset()
	_, err = Run([]string{
		"setup-public-key",
		"--db", dbPath,
		"--out", keyDir,
		"--key-id", "ignored-kid",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("repeat setup-public-key failed: %v stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "exported existing key pair (kid=test-kid-1)") {
		t.Fatalf("expected existing key export, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	_, err = Run([]string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--issuer", "http://localhost:18080",
		"--username", "app",
		"--device-name", "WeChat Bridge",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("issue access token failed: %v stderr=%s", err, stderr.String())
	}
	if strings.Count(strings.TrimSpace(stdout.String()), ".") != 2 {
		t.Fatalf("expected JWT output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	_, err = Run([]string{
		"issue-bridge-runner-token",
		"--db", dbPath,
		"--issuer", "http://localhost:18080",
		"--username", "app",
		"--device-name", "WeChat Bridge",
		"--ttl-seconds", "600",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("issue runner token failed: %v stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "RUNNER_BEARER_TOKEN=") || !strings.Contains(stdout.String(), "RUNNER_BEARER_EXPIRES_AT=") {
		t.Fatalf("unexpected runner output: %s", stdout.String())
	}

	conn, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var keyCount, deviceCount, auditCount int
	if err := conn.QueryRow(`SELECT (SELECT COUNT(*) FROM JWK_KEY_), (SELECT COUNT(*) FROM DEVICE_), (SELECT COUNT(*) FROM TOKEN_AUDIT_)`).Scan(&keyCount, &deviceCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	if keyCount != 1 || deviceCount != 1 || auditCount != 2 {
		t.Fatalf("unexpected db counts: keys=%d devices=%d audits=%d", keyCount, deviceCount, auditCount)
	}
}

func TestIssueBridgeAccessTokenUsesExplicitDeviceID(t *testing.T) {
	t.Setenv("DESKTOP_DEVICE_ID", "")
	root := t.TempDir()
	dbPath := filepath.Join(root, "auth.db")
	keyDir := filepath.Join(root, "keys")
	bootstrapKeys(t, dbPath, keyDir)

	deviceID := "9d8f4d98-14e6-4af9-b60e-6f949560dbb6"
	token := issueBridgeAccessToken(t, []string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--issuer", "http://localhost:18080",
		"--username", "app",
		"--device-name", "Desktop",
		"--device-id", deviceID,
	})
	payload := decodePayload(t, token)
	if payload["device_id"] != deviceID {
		t.Fatalf("expected device_id %s, got %#v", deviceID, payload["device_id"])
	}

	_ = issueBridgeAccessToken(t, []string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--issuer", "http://localhost:18080",
		"--username", "app-two",
		"--device-name", "Renamed In Admin",
		"--device-id", deviceID,
	})

	conn, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var deviceCount, auditCount int
	var deviceName string
	if err := conn.QueryRow(`SELECT (SELECT COUNT(*) FROM DEVICE_), (SELECT COUNT(*) FROM TOKEN_AUDIT_), (SELECT DEVICE_NAME_ FROM DEVICE_ WHERE DEVICE_ID_ = ?)`, deviceID).Scan(&deviceCount, &auditCount, &deviceName); err != nil {
		t.Fatal(err)
	}
	if deviceCount != 1 || auditCount != 2 {
		t.Fatalf("unexpected counts: devices=%d audits=%d", deviceCount, auditCount)
	}
	if deviceName != "Desktop" {
		t.Fatalf("expected existing device name to be preserved, got %q", deviceName)
	}
}

func TestIssueBridgeAccessTokenUsesDesktopDeviceIDEnv(t *testing.T) {
	deviceID := "3f84a4db-3b13-454d-95e4-c11d3534cd21"
	t.Setenv("DESKTOP_DEVICE_ID", deviceID)
	root := t.TempDir()
	dbPath := filepath.Join(root, "auth.db")
	keyDir := filepath.Join(root, "keys")
	bootstrapKeys(t, dbPath, keyDir)

	token := issueBridgeAccessToken(t, []string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--issuer", "http://localhost:18080",
		"--username", "app",
		"--device-name", "Desktop",
	})
	payload := decodePayload(t, token)
	if payload["device_id"] != deviceID {
		t.Fatalf("expected device_id from DESKTOP_DEVICE_ID, got %#v", payload["device_id"])
	}
}

func TestIssueBridgeAccessTokenRejectsInvalidOrRevokedDeviceID(t *testing.T) {
	t.Setenv("DESKTOP_DEVICE_ID", "")
	root := t.TempDir()
	dbPath := filepath.Join(root, "auth.db")
	keyDir := filepath.Join(root, "keys")
	bootstrapKeys(t, dbPath, keyDir)

	var stdout, stderr bytes.Buffer
	_, err := Run([]string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--device-id", "not-a-uuid",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "invalid device-id") {
		t.Fatalf("expected invalid device-id error, got err=%v stderr=%s", err, stderr.String())
	}

	deviceID := "4b5cd6b8-c153-44fd-bf48-cff61d9cc118"
	_ = issueBridgeAccessToken(t, []string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--device-id", deviceID,
		"--device-name", "Desktop",
	})
	conn, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`UPDATE DEVICE_ SET STATUS_ = 'REVOKED' WHERE DEVICE_ID_ = ?`, deviceID); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	_, err = Run([]string{
		"issue-bridge-access-token",
		"--db", dbPath,
		"--device-id", deviceID,
		"--device-name", "Desktop",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected revoked device error, got err=%v stderr=%s", err, stderr.String())
	}
}

func bootstrapKeys(t *testing.T, dbPath, keyDir string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	_, err := Run([]string{
		"setup-public-key",
		"--db", dbPath,
		"--out", keyDir,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("setup-public-key failed: %v stderr=%s", err, stderr.String())
	}
}

func issueBridgeAccessToken(t *testing.T, args []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	handled, err := Run(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("issue access token failed: %v stderr=%s", err, stderr.String())
	}
	if !handled {
		t.Fatal("issue token command was not handled")
	}
	return strings.TrimSpace(stdout.String())
}

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT, got %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
