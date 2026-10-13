package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"identity-center/backend/internal/db"
)

const emailTestSecret = "test-only-secret-32-bytes-long-not-a-production-key"

func emailFixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "email.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.InitEmbeddedSchema(database); err != nil {
		t.Fatal(err)
	}
	if err := db.InitEmbeddedSchema(database); err != nil {
		t.Fatal(err)
	}
	s := New(database)
	u, err := s.CreateUser("alice", "test-password", "Alice", "ACTIVE")
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.CreateAccountSession(u.UserID, "phone")
	if err != nil {
		t.Fatal(err)
	}
	return s, u.UserID, d.Session.DeviceID
}
func emailInput(purpose, email, account, device string) EmailChallengeInput {
	return EmailChallengeInput{Purpose: purpose, Email: email, AccountID: account, DeviceID: device, IP: "192.0.2.1", RequestID: uuid.NewString(), Secret: emailTestSecret, Limits: EmailLimits{EmailHour: 5, EmailDay: 10, AccountHour: 10, AccountDay: 20, IPHour: 30, IPDay: 100, FailureHour: 20}}
}
func reserveEmail(t *testing.T, s *Store, in EmailChallengeInput, now time.Time) (*EmailChallenge, string) {
	t.Helper()
	c, code, fresh, err := s.ReserveEmailChallenge(in, now)
	if err != nil || !fresh {
		t.Fatalf("reserve: %v fresh=%v", err, fresh)
	}
	if err := s.FinishEmailSend(c, true, in.Secret, now); err != nil {
		t.Fatal(err)
	}
	return c, code
}
func consumeEmail(s *Store, c *EmailChallenge, code string, now time.Time) (*EmailConsumeResult, error) {
	return s.ConsumeEmailChallenge(EmailConsumeInput{ID: c.ID, Code: code, Purpose: c.Purpose, AccountID: c.AccountID, DeviceID: c.DeviceID, IP: "192.0.2.1", Secret: emailTestSecret, DeviceName: "phone", FailureHour: 20}, now)
}
func bindEmail(t *testing.T, s *Store, account, device string, now time.Time) {
	t.Helper()
	c, code := reserveEmail(t, s, emailInput("bind", "Alice+tag@Example.COM", account, device), now)
	if _, err := consumeEmail(s, c, code, now); err != nil {
		t.Fatal(err)
	}
}

func TestEmailNormalization(t *testing.T) {
	for _, bad := range []string{"Alice <a@example.com>", "a@example.com\r\nBcc: other@example.com", "a@example.com,b@example.com", "中文@example.com", "a..b@example.com", "a@-example.com"} {
		if _, _, err := NormalizeEmail(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	email, key, err := NormalizeEmail(" Alice.X+tag@Example.COM ")
	if err != nil || email != "Alice.X+tag@Example.COM" || key != "alice.x+tag@example.com" {
		t.Fatal(email, key, err)
	}
}
func TestEmailBindLoginUnbindAndBindingVersion(t *testing.T) {
	s, a, d := emailFixture(t)
	now := time.Now().UTC()
	bindEmail(t, s, a, d, now)
	b, err := s.AccountEmail(a)
	if err != nil || b.Email != "Alice+tag@Example.COM" {
		t.Fatal(b, err)
	}
	login, loginCode := reserveEmail(t, s, emailInput("login", "alice+TAG@example.com", "", ""), now.Add(time.Minute))
	if login.Email != b.Email {
		t.Fatal("did not use verified delivery spelling")
	}
	result, err := consumeEmail(s, login, loginCode, now.Add(time.Minute))
	if err != nil || result.User.UserID != a || result.Session.Session.AccountID != a {
		t.Fatal(result, err)
	}
	if _, err := consumeEmail(s, login, loginCode, now.Add(time.Minute)); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("code replay", err)
	}
	old, oldCode := reserveEmail(t, s, emailInput("login", "alice+tag@example.com", "", ""), now.Add(2*time.Minute))
	unbind, code := reserveEmail(t, s, emailInput("unbind", "", a, d), now.Add(3*time.Minute))
	if _, err := consumeEmail(s, unbind, code, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if b, err := s.AccountEmail(a); b != nil || err != nil {
		t.Fatal(b, err)
	}
	if current, err := s.FindAccountSessionByID(a, d); err != nil || current.Status != "ACTIVE" {
		t.Fatal("unbinding revoked original session")
	}
	if current, err := s.FindAccountSessionByID(a, result.Session.Session.DeviceID); err != nil || current.Status != "ACTIVE" {
		t.Fatal("unbinding revoked other session")
	}
	bindEmail(t, s, a, d, now.Add(4*time.Minute))
	if _, err := consumeEmail(s, old, oldCode, now.Add(4*time.Minute)); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("old binding login revived", err)
	}
	if _, err := consumeEmail(s, unbind, code, now.Add(4*time.Minute)); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("old unbind revived", err)
	}
}
func TestEmailSendDedupFailureAndResend(t *testing.T) {
	s, a, d := emailFixture(t)
	now := time.Now().UTC()
	in := emailInput("bind", "Alice@Example.COM", a, d)
	old, code := reserveEmail(t, s, in, now)
	duplicate, _, fresh, err := s.ReserveEmailChallenge(in, now)
	if err != nil || fresh || duplicate.ID != old.ID {
		t.Fatal("duplicate send", err)
	}
	variant := emailInput("bind", "alice@example.com", a, d)
	if _, _, _, err := s.ReserveEmailChallenge(variant, now); err == nil {
		t.Fatal("case bypassed cooldown")
	}
	failed, failedCode, _, err := s.ReserveEmailChallenge(variant, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishEmailSend(failed, false, emailTestSecret, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.ReserveEmailChallenge(variant, now.Add(2*time.Minute)); !errors.Is(err, ErrEmailSend) {
		t.Fatal("failed request retried", err)
	}
	if _, err := consumeEmail(s, failed, failedCode, now.Add(time.Minute)); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("failed challenge accepted")
	}
	if _, err := consumeEmail(s, old, code, now.Add(time.Minute)); err != nil {
		t.Fatal("failed send destroyed old challenge", err)
	}
}
func TestEmailExpiryPurposeDeviceAndFailureLimits(t *testing.T) {
	s, a, d := emailFixture(t)
	now := time.Now().UTC()
	c, code := reserveEmail(t, s, emailInput("bind", "a@example.com", a, d), now)
	other := EmailConsumeInput{ID: c.ID, Code: code, Purpose: "login", IP: "192.0.2.1", Secret: emailTestSecret, DeviceName: "phone", FailureHour: 20}
	if _, err := s.ConsumeEmailChallenge(other, now); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("cross purpose accepted")
	}
	for range 4 {
		if _, err := consumeEmail(s, c, "notnum", now); !errors.Is(err, ErrEmailChallenge) {
			t.Fatal(err)
		}
		wrong := "000000"
		if code == wrong {
			wrong = "000001"
		}
		if _, err := consumeEmail(s, c, wrong, now); !errors.Is(err, ErrEmailChallenge) {
			t.Fatal(err)
		}
	}
	if _, err := consumeEmail(s, c, code, now); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("five failures did not lock")
	}
	next, nextCode := reserveEmail(t, s, emailInput("bind", "a@example.com", a, d), now.Add(time.Minute))
	if _, err := consumeEmail(s, next, nextCode, now.Add(6*time.Minute)); !errors.Is(err, ErrEmailChallenge) {
		t.Fatal("expired accepted")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT_ FROM EMAIL_LIMIT_ WHERE KIND_='fail-email' AND KEY_=?`, EmailDigest(emailTestSecret, "a@example.com")).Scan(&count); err != nil || count < 6 {
		t.Fatal("failures not persistent", count, err)
	}
}
func TestEmailConcurrentConsumptionAndBinding(t *testing.T) {
	s, a, d := emailFixture(t)
	now := time.Now().UTC()
	c, code := reserveEmail(t, s, emailInput("bind", "a@example.com", a, d), now)
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := consumeEmail(s, c, code, now); results <- err }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrEmailChallenge) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal("consumption winners", wins)
	}
	// Two accounts can receive bind codes before either commits, but only one can bind.
	u, err := s.CreateUser("bob", "test-password", "Bob", "ACTIVE")
	if err != nil {
		t.Fatal(err)
	}
	dev, err := s.CreateAccountSession(u.UserID, "phone")
	if err != nil {
		t.Fatal(err)
	}
	first, x := reserveEmail(t, s, emailInput("bind", "second@example.com", u.UserID, dev.Session.DeviceID), now.Add(time.Minute))
	if err := s.AdminUnbindAccountEmail(a, "admin", "verified ownership", emailTestSecret, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second, y := reserveEmail(t, s, emailInput("bind", "SECOND@example.com", a, d), now.Add(2*time.Minute))
	results = make(chan error, 2)
	for _, pair := range []struct {
		c    *EmailChallenge
		code string
	}{{first, x}, {second, y}} {
		wg.Add(1)
		go func(c *EmailChallenge, code string) {
			defer wg.Done()
			_, err := consumeEmail(s, c, code, now.Add(2*time.Minute))
			results <- err
		}(pair.c, pair.code)
	}
	wg.Wait()
	close(results)
	wins = 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrEmailUnavailable) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal("binding winners", wins)
	}
}
func TestEmailSendAndFailureQuotasSurviveStoreRecreation(t *testing.T) {
	s, a, d := emailFixture(t)
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	for i := range 5 {
		reserveEmail(t, s, emailInput("bind", "a@example.com", a, d), now.Add(time.Duration(i)*time.Minute))
	}
	restarted := New(s.db)
	if _, _, _, err := restarted.ReserveEmailChallenge(emailInput("bind", "A@example.com", a, d), now.Add(5*time.Minute)); err == nil {
		t.Fatal("restart reset hourly send quota")
	}
	c, code := reserveEmail(t, s, emailInput("bind", "other@example.com", a, d), now.Add(6*time.Minute))
	wrong := "000000"
	if wrong == code {
		wrong = "000001"
	}
	for range 3 {
		_, _ = s.ConsumeEmailChallenge(EmailConsumeInput{ID: c.ID, Code: wrong, Purpose: "bind", AccountID: a, DeviceID: d, IP: "192.0.2.1", Secret: emailTestSecret, FailureHour: 3}, now.Add(6*time.Minute))
	}
	if _, err := restarted.ConsumeEmailChallenge(EmailConsumeInput{ID: c.ID, Code: code, Purpose: "bind", AccountID: a, DeviceID: d, IP: "192.0.2.1", Secret: emailTestSecret, FailureHour: 3}, now.Add(6*time.Minute)); err == nil {
		t.Fatal("restart reset failure quota")
	}
}
