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

	"golang.org/x/crypto/bcrypt"

	"zenmind-app-server/backend/internal/config"
	"zenmind-app-server/backend/internal/db"
	"zenmind-app-server/backend/internal/security"
	"zenmind-app-server/backend/internal/store"
)

func newPairingTestServer(t *testing.T) (*Server, func()) {
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
		_ = os.RemoveAll(root)
	}
}

func createDesktopBearerToken(t *testing.T, s *Server, desktopDeviceID string) string {
	t.Helper()
	tokenHash, err := bcrypt.GenerateFromPassword([]byte("desktop-device-token"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash device token: %v", err)
	}
	if _, err := s.store.EnsureActiveDeviceWithID(desktopDeviceID, "ZenMind Desktop", string(tokenHash)); err != nil {
		t.Fatalf("create desktop device: %v", err)
	}
	token, _, _, err := s.issueAppAccessToken(s.cfg.AppUsername, desktopDeviceID, time.Hour)
	if err != nil {
		t.Fatalf("issue desktop token: %v", err)
	}
	return token
}

func postJSON(t *testing.T, handler http.Handler, path string, bearer string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rr.Body.String())
	}
	return body
}

func TestAppPairingStartAndClaimAreOneTime(t *testing.T) {
	s, cleanup := newPairingTestServer(t)
	defer cleanup()
	desktopDeviceID := "9d8f4d98-14e6-4af9-b60e-6f949560dbb6"
	bearer := createDesktopBearerToken(t, s, desktopDeviceID)
	handler := s.Handler()

	startRR := postJSON(t, handler, "/api/auth/pairing/start", bearer, map[string]any{
		"desktopIdentityCreatedAt": "2026-06-01T00:00:00.000Z",
		"desktopUsername":          "alice",
		"desktopHostname":          "workstation",
		"appServerPublicKeySha256": "abc123",
		"apiBaseUrl":               "http://127.0.0.1:8080",
	})
	if startRR.Code != http.StatusCreated {
		t.Fatalf("expected start status 201, got %d body=%s", startRR.Code, startRR.Body.String())
	}
	startBody := decodeBody(t, startRR)
	if startBody["desktopDeviceId"] != desktopDeviceID {
		t.Fatalf("expected desktopDeviceId %s, got %v", desktopDeviceID, startBody["desktopDeviceId"])
	}
	if _, ok := startBody["accessToken"]; ok {
		t.Fatalf("pairing start must not return accessToken: %v", startBody)
	}
	if _, ok := startBody["deviceToken"]; ok {
		t.Fatalf("pairing start must not return deviceToken: %v", startBody)
	}

	claimRR := postJSON(t, handler, "/api/auth/pairing/claim", "", map[string]any{
		"pairingId":  startBody["pairingId"],
		"secret":     startBody["secret"],
		"deviceName": "iPhone",
	})
	if claimRR.Code != http.StatusOK {
		t.Fatalf("expected claim status 200, got %d body=%s", claimRR.Code, claimRR.Body.String())
	}
	claimBody := decodeBody(t, claimRR)
	if claimBody["desktopDeviceId"] != desktopDeviceID {
		t.Fatalf("expected desktopDeviceId %s, got %v", desktopDeviceID, claimBody["desktopDeviceId"])
	}
	if claimBody["deviceId"] == "" || claimBody["deviceId"] == desktopDeviceID {
		t.Fatalf("claim should issue an app device id distinct from desktop: %v", claimBody["deviceId"])
	}
	if claimBody["deviceToken"] == "" || claimBody["accessToken"] == "" {
		t.Fatalf("claim should issue app tokens: %v", claimBody)
	}

	replayRR := postJSON(t, handler, "/api/auth/pairing/claim", "", map[string]any{
		"pairingId":  startBody["pairingId"],
		"secret":     startBody["secret"],
		"deviceName": "iPhone",
	})
	if replayRR.Code != http.StatusBadRequest {
		t.Fatalf("expected replay to fail with 400, got %d body=%s", replayRR.Code, replayRR.Body.String())
	}
}

func TestAppPairingInvalidSecretExpiresAfterLimit(t *testing.T) {
	s, cleanup := newPairingTestServer(t)
	defer cleanup()
	bearer := createDesktopBearerToken(t, s, "0fb83285-f949-49bf-a0d7-e63a4e7f675d")
	handler := s.Handler()

	startRR := postJSON(t, handler, "/api/auth/pairing/start", bearer, map[string]any{})
	if startRR.Code != http.StatusCreated {
		t.Fatalf("expected start status 201, got %d body=%s", startRR.Code, startRR.Body.String())
	}
	startBody := decodeBody(t, startRR)

	for attempt := 0; attempt < appPairingMaxSecretMisses; attempt += 1 {
		rr := postJSON(t, handler, "/api/auth/pairing/claim", "", map[string]any{
			"pairingId":  startBody["pairingId"],
			"secret":     "wrong-secret",
			"deviceName": "iPhone",
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid secret status 400, got %d body=%s", rr.Code, rr.Body.String())
		}
	}

	rr := postJSON(t, handler, "/api/auth/pairing/claim", "", map[string]any{
		"pairingId":  startBody["pairingId"],
		"secret":     startBody["secret"],
		"deviceName": "iPhone",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected ticket to be invalidated after secret misses, got %d body=%s", rr.Code, rr.Body.String())
	}
}
