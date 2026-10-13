package app

import (
	"net/http"
	"sync"
	"testing"
)

func TestAccountLoginChallengeIsBoundAndOneTime(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, confirmer := loginAccountSession(t, s, "alice")

	startRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges", "", map[string]any{"deviceName": "Studio Desktop"})
	if startRR.Code != http.StatusCreated {
		t.Fatalf("start status = %d body=%s", startRR.Code, startRR.Body.String())
	}
	started := decodeBody(t, startRR)
	challengeID := started["challengeId"].(string)
	claimToken := started["claimToken"].(string)
	qrPayload, ok := started["qrPayload"].(map[string]any)
	if !ok || len(qrPayload) != 1 || qrPayload["challengeId"] != challengeID {
		t.Fatalf("QR payload must contain only challengeId: %v", started["qrPayload"])
	}

	pendingClaimRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges/"+challengeID+"/claim", "", map[string]string{"claimToken": claimToken})
	if pendingClaimRR.Code != http.StatusConflict {
		t.Fatalf("pending claim status = %d, want 409", pendingClaimRR.Code)
	}

	confirmRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges/"+challengeID+"/confirm", confirmer["accessToken"].(string), nil)
	if confirmRR.Code != http.StatusOK {
		t.Fatalf("confirm status = %d body=%s", confirmRR.Code, confirmRR.Body.String())
	}

	const claimers = 8
	statuses := make(chan int, claimers)
	var wait sync.WaitGroup
	for range claimers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			rr := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges/"+challengeID+"/claim", "", map[string]string{"claimToken": claimToken})
			statuses <- rr.Code
		}()
	}
	wait.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		} else if status != http.StatusConflict {
			t.Errorf("claim status = %d, want 200 or 409", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successful claims = %d, want exactly one", successes)
	}
}

func TestAccountLoginChallengeFailsAfterConfirmerRevocation(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	_, confirmer := loginAccountSession(t, s, "alice")
	startRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges", "", map[string]any{"deviceName": "Revoked Challenge"})
	started := decodeBody(t, startRR)
	challengeID := started["challengeId"].(string)
	confirmRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges/"+challengeID+"/confirm", confirmer["accessToken"].(string), nil)
	if confirmRR.Code != http.StatusOK {
		t.Fatalf("confirm status = %d body=%s", confirmRR.Code, confirmRR.Body.String())
	}
	logoutRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/logout", confirmer["accessToken"].(string), nil)
	if logoutRR.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d", logoutRR.Code)
	}
	claimRR := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/account/login-challenges/"+challengeID+"/claim", "", map[string]string{"claimToken": started["claimToken"].(string)})
	if claimRR.Code != http.StatusForbidden {
		t.Fatalf("revoked confirmer claim status = %d, want 403 body=%s", claimRR.Code, claimRR.Body.String())
	}
}
