package store

import (
	"path/filepath"
	"testing"

	"identity-center/backend/internal/db"
)

func TestDeviceRefreshClaimsCredentialOnceAndRejectsRevocation(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.InitEmbeddedSchema(conn); err != nil {
		t.Fatal(err)
	}
	s := New(conn)
	limit := 1800
	device, err := s.CreateDevice("voice", "old-credential", &limit)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan bool, 2)
	errors := make(chan error, 2)
	for _, token := range []string{"new-a", "new-b"} {
		go func(token string) { ok, err := s.RefreshDevice(device, token); results <- ok; errors <- err }(token)
	}
	winners := 0
	for i := 0; i < 2; i++ {
		if <-results {
			winners++
		}
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners: %d", winners)
	}
	if _, err := s.FindActiveDeviceByToken("old-credential"); err == nil {
		t.Fatal("old credential still accepted")
	}
	current, err := s.FindDeviceByID(device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.MaxAccessTTLSeconds == nil || *current.MaxAccessTTLSeconds != limit {
		t.Fatal("limit lost during rotation")
	}
	if err := s.RevokeDevice(device.DeviceID); err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"", "new-c"} {
		if ok, err := s.RefreshDevice(current, next); err != nil || ok {
			t.Fatalf("revoked refresh: accepted=%v err=%v", ok, err)
		}
	}
}
