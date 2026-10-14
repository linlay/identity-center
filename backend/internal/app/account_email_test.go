package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"identity-center/backend/internal/config"
	"identity-center/backend/internal/store"
)

func configureEmailTest(s *Server) {
	s.cfg.Email = config.EmailConfig{LoginEnabled: true, BindEnabled: true, Host: "smtp.example.test", Port: 465, TLSMode: "tls", Username: "test", Password: "test", From: "sender@example.test", DigestKey: "test-only-digest-key-longer-than-32-bytes", Timeout: time.Second,
		EmailHour: 5, EmailDay: 10, AccountHour: 10, AccountDay: 20, IPHour: 30, IPDay: 100, FailureHour: 20}
}

func TestDisabledInvalidEmailKeepsCoreAuthenticationAvailable(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	configureEmailTest(s)
	s.cfg.Email.LoginEnabled = false
	s.cfg.Email.BindEnabled = false
	s.cfg.Email.TLSMode = "none"
	s.sendEmail = func(context.Context, string, string, string) error {
		t.Error("invalid email configuration reached SMTP")
		return errors.New("unexpected SMTP call")
	}
	createAccountUser(t, s, "alice")
	rr, session := loginAccountSession(t, s, "alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("invalid disabled email blocked account login: %d", rr.Code)
	}
	token := session["accessToken"].(string)
	for _, path := range []string{"/api/auth/me", "/api/auth/account/security"} {
		if rr := accountRequest(t, s.Handler(), http.MethodGet, path, token, nil); rr.Code != http.StatusOK {
			t.Errorf("invalid disabled email blocked %s: %d", path, rr.Code)
		}
	}
	for _, path := range []string{"/api/auth/account/email/bind/challenges", "/api/auth/account/email/unbind/challenges"} {
		rr := accountRequest(t, s.Handler(), http.MethodPost, path, token, map[string]string{"requestId": uuid.NewString()})
		if rr.Code != http.StatusServiceUnavailable || decodeBody(t, rr)["error"] != "email_unavailable_service" {
			t.Errorf("invalid email configuration did not disable %s: status = %d", path, rr.Code)
		}
	}
	// The existing admin password login and local App Token issuance also remain usable.
	req := httptest.NewRequest(http.MethodPost, "/admin/api/security/app-tokens/issue", strings.NewReader(`{"deviceName":"Legacy Desktop"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminSessionCookie(t, s))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("invalid disabled email blocked legacy App Token issuance: %d", rr.Code)
	}
}

func TestEmailAccountHTTPFlowAndPublicFailureReceipt(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	configureEmailTest(s)
	a := createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	token := session["accessToken"].(string)
	var email, code, purpose string
	sent := 0
	s.sendEmail = func(_ context.Context, to, p, c string) error { sent++; email, purpose, code = to, p, c; return nil }
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/account/security", "", nil); rr.Code != 401 {
		t.Fatal("security exposed without account")
	}
	rr := accountRequest(t, s.Handler(), "GET", "/api/auth/account/security", token, nil)
	if rr.Code != 200 || decodeBody(t, rr)["emailBinding"] != nil {
		t.Fatal("initial security", rr.Body.String())
	}
	req := map[string]string{"email": "Alice+tag@Example.COM", "requestId": uuid.NewString()}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/bind/challenges", token, req)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	challenge := decodeBody(t, rr)["challengeId"]
	if email != "Alice+tag@Example.COM" || purpose != "bind" {
		t.Fatal("wrong delivery target")
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/bind/challenges", token, req)
	if rr.Code != 200 || sent != 1 || decodeBody(t, rr)["challengeId"] != challenge {
		t.Fatal("dedup failed")
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/bind", token, map[string]any{"challengeId": challenge, "code": code})
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if decodeBody(t, rr)["emailBinding"].(map[string]any)["email"] != email {
		t.Fatal("email spelling lost")
	}
	now := time.Now().UTC()
	c, loginCode, _, err := s.store.ReserveEmailChallenge(store.EmailChallengeInput{Purpose: "login", Email: "alice+TAG@example.com", IP: "127.0.0.2", RequestID: uuid.NewString(), Secret: s.cfg.Email.DigestKey, Limits: store.EmailLimits{EmailHour: 5, EmailDay: 10, IPHour: 30, IPDay: 100, FailureHour: 20}}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.FinishEmailSend(c, true, s.cfg.Email.DigestKey, now); err != nil {
		t.Fatal(err)
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/login", "", map[string]any{"challengeId": c.ID, "code": loginCode, "deviceName": "Email Phone"})
	if rr.Code != 200 || decodeBody(t, rr)["accountId"] != a {
		t.Fatal("login", rr.Body.String())
	}
	// Rollback disables new login/binding while valid SMTP still permits unbinding.
	s.cfg.Email.LoginEnabled = false
	s.cfg.Email.BindEnabled = false
	unbind, unbindCode, _, err := s.store.ReserveEmailChallenge(store.EmailChallengeInput{Purpose: "unbind", AccountID: a, DeviceID: session["deviceId"].(string), IP: "127.0.0.2", RequestID: uuid.NewString(), Secret: s.cfg.Email.DigestKey, Limits: store.EmailLimits{EmailHour: 5, EmailDay: 10, AccountHour: 10, AccountDay: 20, IPHour: 30, IPDay: 100, FailureHour: 20}}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.FinishEmailSend(unbind, true, s.cfg.Email.DigestKey, now); err != nil {
		t.Fatal(err)
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/unbind", token, map[string]any{"challengeId": unbind.ID, "code": unbindCode})
	if rr.Code != 200 || decodeBody(t, rr)["emailBinding"] != nil {
		t.Fatal("unbind", rr.Body.String())
	}
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", token, nil); rr.Code != 200 {
		t.Fatal("unbind logged out account")
	}
	s.cfg.Email.LoginEnabled = true
	s.cfg.Email.BindEnabled = true
	// Unknown addresses get the same opaque public receipt, with no mail delivery.
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/challenges", "", map[string]string{"email": "unknown@example.com", "requestId": uuid.NewString()})
	if rr.Code != 200 || sent != 1 {
		t.Fatal("unknown mailbox flow")
	}
	receipt := decodeBody(t, rr)
	if len(receipt) != 5 || strings.Contains(rr.Body.String(), "unknown@example.com") {
		t.Fatal("public receipt leaked mailbox or delivery status")
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/login", "", map[string]any{"challengeId": receipt["challengeId"], "code": "000000", "deviceName": "Phone"})
	if rr.Code != 401 || decodeBody(t, rr)["error"] != "email_authentication_failed" {
		t.Fatal("fake challenge authenticated")
	}
}
func TestEmailPublicSMTPFaultDoesNotRevealBinding(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	configureEmailTest(s)
	a := createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	now := time.Now().UTC()
	in := store.EmailChallengeInput{Purpose: "bind", Email: "a@example.com", AccountID: a, DeviceID: session["deviceId"].(string), IP: "127.0.0.1", RequestID: uuid.NewString(), Secret: s.cfg.Email.DigestKey, Limits: store.EmailLimits{EmailHour: 5, EmailDay: 10, AccountHour: 10, AccountDay: 20, IPHour: 30, IPDay: 100, FailureHour: 20}}
	c, code, _, err := s.store.ReserveEmailChallenge(in, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.FinishEmailSend(c, true, in.Secret, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.ConsumeEmailChallenge(store.EmailConsumeInput{ID: c.ID, Code: code, Purpose: "bind", AccountID: a, DeviceID: session["deviceId"].(string), IP: in.IP, Secret: in.Secret, FailureHour: 20}, now); err != nil {
		t.Fatal(err)
	}
	s.sendEmail = func(context.Context, string, string, string) error { return errors.New("SMTP unknown") }
	req := map[string]string{"email": "a@example.com", "requestId": uuid.NewString()}
	rr := accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/challenges", "", req)
	if rr.Code != 200 {
		t.Fatal("fault leaked via status", rr.Code)
	}
	receipt := decodeBody(t, rr)
	duplicate := accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/challenges", "", req)
	if duplicate.Code != 200 || decodeBody(t, duplicate)["challengeId"] != receipt["challengeId"] {
		t.Fatal("failed request duplicate leaked state")
	}
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/login", "", map[string]any{"challengeId": receipt["challengeId"], "code": "000000", "deviceName": "Phone"})
	if rr.Code != 401 {
		t.Fatal("unconfirmed send authenticated")
	}
	if rr := accountRequest(t, s.Handler(), http.MethodPost, "/admin/api/users/"+a+"/email/unbind", "", map[string]any{"reason": "test", "confirmed": true}); rr.Code != 401 {
		t.Fatal("admin unbind exposed")
	}
	s.cfg.Email.LoginEnabled = false
	if rr := accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/challenges", "", req); rr.Code != 503 {
		t.Fatal("login kill switch ignored")
	}
	// Disabling new entry points does not hide the existing binding or revoke its sessions.
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/account/security", session["accessToken"].(string), nil); rr.Code != 200 {
		t.Fatal("rollback hid security")
	}
}

func TestEmailUnbindDuringDeliveryStillReturnsOpaqueReceipt(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	configureEmailTest(s)
	a := createAccountUser(t, s, "alice")
	_, session := loginAccountSession(t, s, "alice")
	now := time.Now().UTC()
	input := store.EmailChallengeInput{Purpose: "bind", Email: "a@example.com", AccountID: a, DeviceID: session["deviceId"].(string), IP: "127.0.0.1", RequestID: uuid.NewString(), Secret: s.cfg.Email.DigestKey, Limits: store.EmailLimits{EmailHour: 5, EmailDay: 10, AccountHour: 10, AccountDay: 20, IPHour: 30, IPDay: 100, FailureHour: 20}}
	c, code, _, err := s.store.ReserveEmailChallenge(input, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.FinishEmailSend(c, true, input.Secret, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.ConsumeEmailChallenge(store.EmailConsumeInput{ID: c.ID, Code: code, Purpose: "bind", AccountID: a, DeviceID: input.DeviceID, IP: input.IP, Secret: input.Secret, FailureHour: 20}, now); err != nil {
		t.Fatal(err)
	}
	var loginCode string
	s.sendEmail = func(_ context.Context, to, purpose, code string) error {
		loginCode = code
		return s.store.AdminUnbindAccountEmail(a, "admin", "verified ownership", input.Secret, time.Now().UTC())
	}
	rr := accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/challenges", "", map[string]string{"email": "a@example.com", "requestId": uuid.NewString()})
	if rr.Code != 200 {
		t.Fatal("concurrent unbind exposed through public receipt", rr.Code)
	}
	receipt := decodeBody(t, rr)
	rr = accountRequest(t, s.Handler(), "POST", "/api/auth/account/email/login", "", map[string]any{"challengeId": receipt["challengeId"], "code": loginCode, "deviceName": "phone"})
	if rr.Code != 401 {
		t.Fatal("code survived unbind during SMTP delivery")
	}
	if rr := accountRequest(t, s.Handler(), "GET", "/api/auth/me", session["accessToken"].(string), nil); rr.Code != 200 {
		t.Fatal("admin unbind revoked session")
	}
}
