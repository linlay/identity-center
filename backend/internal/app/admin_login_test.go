package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-center/backend/internal/config"
	"identity-center/backend/internal/model"
)

const (
	testAdminPassword       = "password"
	testAdminPasswordBcrypt = "$2a$10$R9SBw8NUY53nl9mg4L206eM0gFmQFqxSIg5ieLKILAiNbbc2ZSVbu"
)

func newAdminLoginTestServer(logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		cfg: &config.Config{
			AdminUsername:       "admin",
			AdminPasswordBcrypt: testAdminPasswordBcrypt,
		},
		logger:        logger,
		adminSessions: map[string]model.AdminSession{},
	}
}

func runAdminLogin(t *testing.T, s *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/session/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.10:55000"
	rr := httptest.NewRecorder()
	s.handleAdminLogin(rr, req)
	return rr
}

func TestHandleAdminLoginSuccessSetsSessionCookie(t *testing.T) {
	s := newAdminLoginTestServer(nil)
	rr := runAdminLogin(t, s, "admin", testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d, body=%s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["username"] != "admin" {
		t.Fatalf("expected username admin in response, got: %v", body["username"])
	}

	cookies := rr.Result().Cookies()
	foundSessionCookie := false
	for _, cookie := range cookies {
		if cookie.Name == adminSessionCookieName && strings.TrimSpace(cookie.Value) != "" {
			foundSessionCookie = true
			break
		}
	}
	if !foundSessionCookie {
		t.Fatalf("expected %s cookie to be set", adminSessionCookieName)
	}
	if len(s.adminSessions) != 1 {
		t.Fatalf("expected 1 admin session, got: %d", len(s.adminSessions))
	}
}

func TestHandleAdminLoginRejectsWrongPassword(t *testing.T) {
	s := newAdminLoginTestServer(nil)
	rr := runAdminLogin(t, s, "admin", "wrong-password")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid admin credentials") {
		t.Fatalf("expected invalid credentials error, got: %s", rr.Body.String())
	}
}

func TestHandleAdminLoginRejectsWrongUsername(t *testing.T) {
	s := newAdminLoginTestServer(nil)
	rr := runAdminLogin(t, s, "other-admin", testAdminPassword)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid admin credentials") {
		t.Fatalf("expected invalid credentials error, got: %s", rr.Body.String())
	}
}

func TestHandleAdminLoginTrimsUsernameBeforeCompare(t *testing.T) {
	s := newAdminLoginTestServer(nil)
	rr := runAdminLogin(t, s, "  admin  ", testAdminPassword)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d, body=%s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestHandleAdminLoginFailureLogsDiagnosticsWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	s := newAdminLoginTestServer(log.New(&logs, "", 0))

	_ = runAdminLogin(t, s, "admin", "not-the-password")
	logOutput := logs.String()
	if !strings.Contains(logOutput, "admin login failed:") {
		t.Fatalf("expected failure log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "username_match=true") || !strings.Contains(logOutput, "password_match=false") {
		t.Fatalf("expected password mismatch diagnostics in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "remote=198.51.100.10:55000") {
		t.Fatalf("expected remote address in log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "not-the-password") {
		t.Fatalf("log must not include raw password, got: %s", logOutput)
	}
	if strings.Contains(logOutput, testAdminPasswordBcrypt) {
		t.Fatalf("log must not include bcrypt hash, got: %s", logOutput)
	}

	logs.Reset()
	_ = runAdminLogin(t, s, "other-admin", testAdminPassword)
	logOutput = logs.String()
	if !strings.Contains(logOutput, "username_match=false") || !strings.Contains(logOutput, "password_match=true") {
		t.Fatalf("expected username mismatch diagnostics in log, got: %s", logOutput)
	}
}
