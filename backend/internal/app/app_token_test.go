package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"identity-center/backend/internal/config"
	"identity-center/backend/internal/db"
	"identity-center/backend/internal/security"
	"identity-center/backend/internal/store"
)

func newAppAccessTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	root := t.TempDir()
	conn, err := db.Open(filepath.Join(root, "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitEmbeddedSchema(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("init schema: %v", err)
	}
	s, err := New(&config.Config{
		Issuer:               "http://127.0.0.1:8080",
		AdminUsername:        "admin",
		AdminPasswordBcrypt:  testAdminPasswordBcrypt,
		AppUsername:          "app",
		AppAccessTTL:         time.Hour,
		AppMaxAccessTTL:      24 * time.Hour,
		AppRotateDeviceToken: true,
		CleanupRetention:     time.Hour,
		CleanupCron:          "0 0 * * * *",
	}, store.New(conn), security.NewKeyManager(conn), log.New(io.Discard, "", 0))
	if err != nil {
		_ = conn.Close()
		t.Fatalf("new server: %v", err)
	}
	return s, func() {
		s.Close()
		_ = conn.Close()
	}
}

func adminSessionCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	})
	if err != nil {
		t.Fatalf("marshal admin login: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/session/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin login status = %d, body=%s", rr.Code, rr.Body.String())
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == adminSessionCookieName {
			return cookie
		}
	}
	t.Fatalf("admin login did not set %s cookie", adminSessionCookieName)
	return nil
}

func TestAdminIssueAppTokenDoesNotRequireMasterPassword(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()

	payload, err := json.Marshal(map[string]any{
		"deviceName":       "Admin Console Device",
		"accessTtlSeconds": 600,
	})
	if err != nil {
		t.Fatalf("marshal issue request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/security/app-tokens/issue", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminSessionCookie(t, s))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("issue app token status = %d, body=%s", rr.Code, rr.Body.String())
	}

	body := decodeBody(t, rr)
	if body["username"] != "app" {
		t.Fatalf("username = %v, want app", body["username"])
	}
	if body["deviceName"] != "Admin Console Device" {
		t.Fatalf("deviceName = %v", body["deviceName"])
	}
	if body["accessToken"] == "" || body["deviceToken"] == "" {
		t.Fatalf("expected access and device tokens, got: %v", body)
	}
}

func TestLegacyAppMasterPasswordRoutesAreRemoved(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()

	legacyLogin := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{}`)))
	legacyLogin.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	s.Handler().ServeHTTP(loginRR, legacyLogin)
	if loginRR.Code != http.StatusNotFound {
		t.Fatalf("legacy app login status = %d, want 404", loginRR.Code)
	}

	publicGate := httptest.NewRequest(http.MethodGet, "/api/auth/new-device-access", nil)
	publicGateRR := httptest.NewRecorder()
	s.Handler().ServeHTTP(publicGateRR, publicGate)
	if publicGateRR.Code != http.StatusNotFound {
		t.Fatalf("legacy public new-device-access status = %d, want 404", publicGateRR.Code)
	}

	adminGate := httptest.NewRequest(http.MethodGet, "/admin/api/security/new-device-access", nil)
	adminGate.AddCookie(adminSessionCookie(t, s))
	adminGateRR := httptest.NewRecorder()
	s.Handler().ServeHTTP(adminGateRR, adminGate)
	if adminGateRR.Code != http.StatusNotFound {
		t.Fatalf("legacy admin new-device-access status = %d, want 404", adminGateRR.Code)
	}
}
