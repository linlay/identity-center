package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math"
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

func deviceRequest(t *testing.T, s *Server, path string, payload map[string]any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestDeviceAccessLimitAppliesToIssueRefreshAndInvalidRequestsDoNotRotate(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	cookie := adminSessionCookie(t, s)
	issuePath := "/admin/api/security/app-tokens/issue"
	for _, ttl := range []int{0, -1, 1801, math.MaxInt} {
		rr := deviceRequest(t, s, issuePath, map[string]any{"deviceName": "voice", "maxAccessTtlSeconds": 1800, "accessTtlSeconds": ttl}, cookie)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid issue TTL %d accepted", ttl)
		}
	}
	rr := deviceRequest(t, s, issuePath, map[string]any{"deviceName": "voice", "maxAccessTtlSeconds": 1800}, cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("issue status=%d", rr.Code)
	}
	issued := decodeBody(t, rr)
	assertDeviceTTL(t, s, issued["accessToken"].(string), 1800)
	credential := issued["deviceToken"].(string)
	device, err := s.store.FindActiveDeviceByToken(credential)
	if err != nil {
		t.Fatal(err)
	}
	if device.MaxAccessTTLSeconds == nil || *device.MaxAccessTTLSeconds != 1800 {
		t.Fatal("limit not persisted")
	}
	for _, ttl := range []int{0, -1, 1801, math.MaxInt} {
		rr = deviceRequest(t, s, "/api/auth/refresh", map[string]any{"deviceToken": credential, "accessTtlSeconds": ttl}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid refresh TTL %d accepted", ttl)
		}
		current, err := s.store.FindActiveDeviceByToken(credential)
		if err != nil || current.DeviceTokenBcrypt != device.DeviceTokenBcrypt {
			t.Fatal("invalid TTL rotated credential")
		}
	}
	rr = deviceRequest(t, s, "/api/auth/refresh", map[string]any{"deviceToken": credential, "maxAccessTtlSeconds": 86400}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status=%d", rr.Code)
	}
	refreshed := decodeBody(t, rr)
	assertDeviceTTL(t, s, refreshed["accessToken"].(string), 1800) // A refresh cannot override the persisted cap.
	if refreshed["deviceToken"] == credential {
		t.Fatal("valid refresh failed to rotate")
	}
	if rr := deviceRequest(t, s, "/api/auth/refresh", map[string]any{"deviceToken": credential}, nil); rr.Code != http.StatusBadRequest {
		t.Fatal("old token accepted")
	}
	if err := s.store.RevokeDevice(device.DeviceID); err != nil {
		t.Fatal(err)
	}
	if rr := deviceRequest(t, s, "/api/auth/refresh", map[string]any{"deviceToken": refreshed["deviceToken"]}, nil); rr.Code != http.StatusBadRequest {
		t.Fatal("revoked device refreshed")
	}
}

func assertDeviceTTL(t *testing.T, s *Server, token string, seconds int64) {
	t.Helper()
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{}
	if err := security.ParseAndVerifyJWT(token, key, &claims); err != nil {
		t.Fatal(err)
	}
	if int64(claims["exp"].(float64)-claims["iat"].(float64)) != seconds {
		t.Fatal("incorrect JWT TTL")
	}
	if claims["sub"] != s.cfg.AppUsername || claims["iss"] != s.cfg.Issuer || claims["device_id"] == "" {
		t.Fatal("device replaced owner identity")
	}
}

func TestLegacyDeviceTTLAndNonRotatingRefreshKeepExistingPolicy(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	s.cfg.AppRotateDeviceToken = false
	rr := deviceRequest(t, s, "/admin/api/security/app-tokens/issue", map[string]any{"deviceName": "legacy"}, adminSessionCookie(t, s))
	if rr.Code != http.StatusOK {
		t.Fatalf("issue status=%d", rr.Code)
	}
	issued := decodeBody(t, rr)
	assertDeviceTTL(t, s, issued["accessToken"].(string), 3600)
	credential := issued["deviceToken"].(string)
	rr = deviceRequest(t, s, "/api/auth/refresh", map[string]any{"deviceToken": credential, "accessTtlSeconds": 7200}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status=%d", rr.Code)
	}
	refreshed := decodeBody(t, rr)
	assertDeviceTTL(t, s, refreshed["accessToken"].(string), 7200)
	if refreshed["deviceToken"] != credential {
		t.Fatal("rotation policy changed")
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
