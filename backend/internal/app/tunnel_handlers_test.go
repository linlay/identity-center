package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-center/backend/internal/config"
	"identity-center/backend/internal/db"
	"identity-center/backend/internal/security"
	"identity-center/backend/internal/store"
)

func newTunnelTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	root := t.TempDir()
	conn, err := db.Open(filepath.Join(root, "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitEmbeddedSchema(conn); err != nil {
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
		TunnelHubBaseDomain:  "zenmind.cc",
		TunnelHubRelayURL:    "wss://relay.example.test/tunnel",
	}, store.New(conn), security.NewKeyManager(conn), log.New(io.Discard, "", 0))
	if err != nil {
		_ = conn.Close()
		t.Fatalf("new server: %v", err)
	}
	return s, func() {
		s.Close()
		_ = conn.Close()
		_ = os.RemoveAll(root)
	}
}

func tunnelJSONRequest(t *testing.T, method, path string, payload any) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func tunnelAdminCookies(t *testing.T, handler http.Handler) []*http.Cookie {
	t.Helper()
	req := tunnelJSONRequest(t, http.MethodPost, "/admin/api/session/login", map[string]any{
		"username": "admin",
		"password": testAdminPassword,
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin login status=%d body=%s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req
}

func tunnelAppBearer(t *testing.T, s *Server) string {
	t.Helper()
	device, err := s.store.CreateDevice("Site Browser", "site-device-token")
	if err != nil {
		t.Fatalf("create app device: %v", err)
	}
	token, _, _, err := s.issueAppAccessToken(s.cfg.AppUsername, device.DeviceID, time.Hour)
	if err != nil {
		t.Fatalf("issue app token: %v", err)
	}
	return token
}

func TestTunnelDesktopRegistrationAndAdminControls(t *testing.T) {
	s, cleanup := newTunnelTestServer(t)
	defer cleanup()
	handler := s.Handler()

	registerReq := tunnelJSONRequest(t, http.MethodPost, "/api/desktop/devices/register", map[string]any{
		"deviceId":    "mac-mini-office",
		"deviceName":  "Mac Mini Office",
		"rotateToken": true,
	})
	registerReq.Header.Set("Authorization", "Bearer "+tunnelAppBearer(t, s))
	registerRR := httptest.NewRecorder()
	handler.ServeHTTP(registerRR, registerReq)
	if registerRR.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", registerRR.Code, registerRR.Body.String())
	}
	var registerBody map[string]any
	if err := json.NewDecoder(registerRR.Body).Decode(&registerBody); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	if registerBody["agentToken"] == "" {
		t.Fatalf("expected agentToken in registration response: %v", registerBody)
	}
	if registerBody["publicHost"] != "mac-mini-office.m.zenmind.cc" {
		t.Fatalf("unexpected public host: %v", registerBody["publicHost"])
	}
	if registerBody["relayUrl"] != "wss://relay.example.test/tunnel" {
		t.Fatalf("unexpected relayUrl: %v", registerBody["relayUrl"])
	}

	cookies := tunnelAdminCookies(t, handler)
	listReq := withCookies(httptest.NewRequest(http.MethodGet, "/admin/api/tunnel/desktops?q=mini", nil), cookies)
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list desktops status=%d body=%s", listRR.Code, listRR.Body.String())
	}
	var desktops []map[string]any
	if err := json.NewDecoder(listRR.Body).Decode(&desktops); err != nil {
		t.Fatalf("decode desktops: %v", err)
	}
	if len(desktops) != 1 || desktops[0]["deviceId"] != "mac-mini-office" {
		t.Fatalf("unexpected desktop rows: %#v", desktops)
	}
	if _, ok := desktops[0]["agentToken"]; ok {
		t.Fatalf("admin desktop rows must not expose agentToken: %#v", desktops[0])
	}

	closeReq := withCookies(httptest.NewRequest(http.MethodPost, "/admin/api/tunnel/desktops/mac-mini-office/close", nil), cookies)
	closeRR := httptest.NewRecorder()
	handler.ServeHTTP(closeRR, closeReq)
	if closeRR.Code != http.StatusOK {
		t.Fatalf("close status=%d body=%s", closeRR.Code, closeRR.Body.String())
	}

	disableReq := withCookies(tunnelJSONRequest(t, http.MethodPatch, "/admin/api/tunnel/desktops/mac-mini-office", map[string]any{"enabled": false}), cookies)
	disableRR := httptest.NewRecorder()
	handler.ServeHTTP(disableRR, disableReq)
	if disableRR.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disableRR.Code, disableRR.Body.String())
	}
	var disabled map[string]any
	if err := json.NewDecoder(disableRR.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode disabled: %v", err)
	}
	if disabled["enabled"] != false || disabled["status"] != "DISABLED" {
		t.Fatalf("expected disabled desktop, got: %#v", disabled)
	}

	overviewReq := withCookies(httptest.NewRequest(http.MethodGet, "/admin/api/tunnel/overview?bucket=day", nil), cookies)
	overviewRR := httptest.NewRecorder()
	handler.ServeHTTP(overviewRR, overviewReq)
	if overviewRR.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", overviewRR.Code, overviewRR.Body.String())
	}
	var overview map[string]any
	if err := json.NewDecoder(overviewRR.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	resources := overview["resources"].(map[string]any)
	if resources["disabledDesktops"] != float64(1) {
		t.Fatalf("expected disabled desktop resource count, got: %#v", resources)
	}

	activityReq := withCookies(httptest.NewRequest(http.MethodGet, "/admin/api/tunnel/activity?type=desktop", nil), cookies)
	activityRR := httptest.NewRecorder()
	handler.ServeHTTP(activityRR, activityReq)
	if activityRR.Code != http.StatusOK {
		t.Fatalf("activity status=%d body=%s", activityRR.Code, activityRR.Body.String())
	}
	var activities []map[string]any
	if err := json.NewDecoder(activityRR.Body).Decode(&activities); err != nil {
		t.Fatalf("decode activity: %v", err)
	}
	if len(activities) < 3 {
		t.Fatalf("expected registration, close, and disable activities, got: %#v", activities)
	}
}

func TestManualAppTokenIssueEndpointRemovedButRefreshRemains(t *testing.T) {
	s, cleanup := newTunnelTestServer(t)
	defer cleanup()
	handler := s.Handler()
	cookies := tunnelAdminCookies(t, handler)

	issueReq := withCookies(tunnelJSONRequest(t, http.MethodPost, "/admin/api/security/app-tokens/issue", map[string]any{}), cookies)
	issueRR := httptest.NewRecorder()
	handler.ServeHTTP(issueRR, issueReq)
	if issueRR.Code != http.StatusNotFound {
		t.Fatalf("expected issue endpoint removed with 404, got %d body=%s", issueRR.Code, issueRR.Body.String())
	}

	refreshReq := withCookies(tunnelJSONRequest(t, http.MethodPost, "/admin/api/security/app-tokens/refresh", map[string]any{}), cookies)
	refreshRR := httptest.NewRecorder()
	handler.ServeHTTP(refreshRR, refreshReq)
	if refreshRR.Code == http.StatusNotFound {
		t.Fatalf("refresh endpoint must remain available")
	}
}
