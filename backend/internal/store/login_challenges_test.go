package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"identity-center/backend/internal/db"
)

func TestLoginChallengeExpires(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "challenge.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer database.Close()
	if err := db.InitEmbeddedSchema(database); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st := New(database)
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	created, err := st.CreateLoginChallenge("Phone", now, 2*time.Minute)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if _, err := st.FindLoginChallenge(created.Challenge.ChallengeID, now.Add(2*time.Minute)); err != ErrLoginChallengeExpired {
		t.Fatalf("find at expiry error = %v, want %v", err, ErrLoginChallengeExpired)
	}
}

func TestExpiredLoginChallengeCleanupKeepsCurrentAndRecentlyExpired(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.InitEmbeddedSchema(database); err != nil {
		t.Fatal(err)
	}
	st := New(database)
	now := time.Now().UTC()
	for _, at := range []time.Time{now.Add(-3 * time.Hour), now.Add(-3 * time.Minute), now} {
		if _, err := st.CreateLoginChallenge("Phone", at, 2*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := st.DeleteExpiredLoginChallengesOlderThan(0); err != nil || deleted != 0 {
		t.Fatalf("disabled cleanup: %d %v", deleted, err)
	}
	if deleted, err := st.DeleteExpiredLoginChallengesOlderThan(time.Hour); err != nil || deleted != 1 {
		t.Fatalf("cleanup deleted = %d, error = %v", deleted, err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM LOGIN_CHALLENGE_`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("remaining challenges = %d, error = %v", count, err)
	}
}

func TestTouchAccountSessionRejectsRevokedSession(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.InitEmbeddedSchema(database); err != nil {
		t.Fatal(err)
	}
	st := New(database)
	created, err := st.CreateAccountSession("account", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.TouchAccountSession("account", created.Session.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeAccountSession("account", created.Session.DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchAccountSession("account", created.Session.DeviceID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoked session touch = %v", err)
	}
}
