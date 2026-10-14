package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func accountRequest(t *testing.T, handler http.Handler, method, path, bearer string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func createAccountUser(t *testing.T, s *Server, username string) string {
	t.Helper()
	user, err := s.store.CreateUser(username, "correct horse battery staple", username, "ACTIVE")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.UserID
}

func loginAccountSession(t *testing.T, s *Server, username string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login", "", map[string]any{
		"username": username, "password": "correct horse battery staple", "deviceName": username + " phone",
	})
	if rr.Code != http.StatusOK {
		return rr, nil
	}
	return rr, decodeBody(t, rr)
}

func TestAccountSessionLifecycleAndLegacyIsolation(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	accountID := createAccountUser(t, s, "alice")
	createAccountUser(t, s, "bob")
	rr, alice := loginAccountSession(t, s, "alice")
	if rr.Code != 200 || alice["accountId"] != accountID || alice["deviceToken"] == "" {
		t.Fatalf("login failed: %s", rr.Body.String())
	}
	_, bob := loginAccountSession(t, s, "bob")
	for _, request := range []struct{ method, path string }{
		{"GET", "/api/auth/devices"}, {"PATCH", "/api/auth/devices/" + bob["deviceId"].(string)}, {"DELETE", "/api/auth/devices/" + bob["deviceId"].(string)},
	} {
		result := accountRequest(t, s.Handler(), request.method, request.path, alice["accessToken"].(string), map[string]string{"deviceName": "changed"})
		if result.Code != 403 {
			t.Fatalf("legacy namespace exposed: %s %s = %d", request.method, request.path, result.Code)
		}
	}
	audits, err := s.store.ListTokenAudits(nil, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if audit.Source == "ACCOUNT_APP_ACCESS" && (audit.Token != "" || audit.TokenSHA256 == "") {
			t.Fatal("account token audit exposed credential")
		}
	}
	oldToken := alice["deviceToken"].(string)
	refresh := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]string{"deviceToken": oldToken})
	if refresh.Code != 200 {
		t.Fatalf("refresh failed: %s", refresh.Body.String())
	}
	next := decodeBody(t, refresh)
	if next["deviceToken"] == oldToken || next["accountId"] != accountID {
		t.Fatal("refresh did not rotate account credential")
	}
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]string{"deviceToken": oldToken}); rr.Code != http.StatusUnauthorized {
		t.Fatal("old refresh credential accepted")
	}
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/logout", next["accessToken"].(string), nil); rr.Code != 204 {
		t.Fatal("logout failed")
	}
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", next["accessToken"].(string), nil); rr.Code != 401 {
		t.Fatal("revoked session accepted")
	}
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", bob["accessToken"].(string), nil); rr.Code != 200 {
		t.Fatal("logout revoked another session")
	}
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]any{"deviceToken": next["deviceToken"]}); rr.Code != http.StatusUnauthorized {
		t.Fatal("revoked credential refreshed")
	}
}

func TestInactiveAccountCannotUseSession(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	id := createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	if _, err := s.store.UpdateUser(id, "alice", "DISABLED"); err != nil {
		t.Fatal(err)
	}
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", session["accessToken"].(string), nil); rr.Code != 401 {
		t.Fatal("disabled account accepted")
	}
}

func TestConcurrentAccountRefreshRotatesCredentialOnce(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	statuses := make(chan int, 4)
	var wait sync.WaitGroup
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			rr := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/refresh", "", map[string]any{"deviceToken": session["deviceToken"]})
			statuses <- rr.Code
		}()
	}
	wait.Wait()
	close(statuses)
	winners := 0
	for status := range statuses {
		if status == http.StatusOK {
			winners++
		} else if status != http.StatusUnauthorized {
			t.Errorf("refresh status = %d", status)
		}
	}
	if winners != 1 {
		t.Fatalf("refresh winners = %d, want one", winners)
	}
}

func TestRetiredAuthenticationEndpointsAreNotReachable(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	for _, request := range []struct{ method, path string }{
		{"POST", "/api/auth/pairing/start"},
		{"POST", "/api/auth/pairing/claim"},
		{"POST", "/api/auth/account/login-challenges"},
		{"POST", "/api/auth/account/login-challenges/11111111-1111-4111-8111-111111111111/confirm"},
		{"POST", "/api/auth/account/login-challenges/11111111-1111-4111-8111-111111111111/claim"},
	} {
		if rr := accountRequest(t, s.Handler(), request.method, request.path, session["accessToken"].(string), nil); rr.Code != http.StatusNotFound {
			t.Fatalf("retired route %s %s is still reachable: %d", request.method, request.path, rr.Code)
		}
	}
}

func TestAccountMeReturnsBoundIdentityAndIssueTime(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	accountID := createAccountUser(t, s, "alice")
	before := time.Now().Truncate(time.Second)
	_, session := loginAccountSession(t, s, "alice")
	rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", session["accessToken"].(string), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("me status = %d", rr.Code)
	}
	me := decodeBody(t, rr)
	issuedAt, err := time.Parse(time.RFC3339, me["issuedAt"].(string))
	if err != nil || issuedAt.Before(before) || issuedAt.After(time.Now()) {
		t.Fatalf("invalid issue time: %v", me["issuedAt"])
	}
	if me["schemaVersion"] != float64(1) || me["accountId"] != accountID || me["deviceId"] != session["deviceId"] {
		t.Fatal("account identity mismatch")
	}
}

func TestAccountRefreshRejectsInactiveAccountWithoutRotatingCredential(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	id := createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	if _, err := s.store.UpdateUser(id, "alice", "DISABLED"); err != nil {
		t.Fatal(err)
	}
	rr := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]any{"deviceToken": session["deviceToken"]})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("disabled account refresh status = %d", rr.Code)
	}
	if _, err := s.store.UpdateUser(id, "alice", "ACTIVE"); err != nil {
		t.Fatal(err)
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]any{"deviceToken": session["deviceToken"]})
	if rr.Code != http.StatusOK {
		t.Fatalf("credential was changed after rejected refresh: %d", rr.Code)
	}
}

func TestAccountLogoutReportsFailedRevocation(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	if err := s.store.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER fail_account_revoke BEFORE UPDATE OF STATUS_ ON DEVICE_ WHEN NEW.ACCOUNT_ID_ != '' BEGIN SELECT RAISE(ABORT, 'revocation unavailable'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rr := accountRequest(t, s.Handler(), "POST", "/api/auth/logout", session["accessToken"].(string), nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("failed revocation reported as successful: %d", rr.Code)
	}
}

func TestAccountAuthenticationRejectsRevocationDuringSessionTouch(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	if err := s.store.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER revoke_during_touch BEFORE UPDATE OF LAST_SEEN_AT_ ON DEVICE_ WHEN NEW.ACCOUNT_ID_ != '' BEGIN UPDATE DEVICE_ SET STATUS_ = 'REVOKED' WHERE DEVICE_ID_ = NEW.DEVICE_ID_; SELECT RAISE(IGNORE); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", session["accessToken"].(string), nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked-during-validation session accepted: %d", rr.Code)
	}
}

func TestAccountRefreshWithoutRotationKeepsCredentialUntilLogout(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	s.cfg.AppRotateDeviceToken = false
	createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	for range 2 {
		rr := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]any{"deviceToken": session["deviceToken"]})
		if rr.Code != http.StatusOK {
			t.Fatalf("non-rotating refresh status = %d", rr.Code)
		}
		next := decodeBody(t, rr)
		if next["deviceToken"] != session["deviceToken"] || next["accountId"] != session["accountId"] {
			t.Fatal("non-rotating refresh changed credential or account")
		}
		session = next
	}
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/logout", session["accessToken"].(string), nil); rr.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d", rr.Code)
	}
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/refresh", "", map[string]any{"deviceToken": session["deviceToken"]}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked non-rotating credential accepted: %d", rr.Code)
	}
}
