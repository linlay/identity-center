package app

import (
	"net/http"
	"testing"
	"time"

	"identity-center/backend/internal/security"
)

func TestOIDCUserInfoRejectsAppTokensBeforeAndAfterLogout(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	createAccountUser(t, s, "alice")
	rr, account := loginAccountSession(t, s, "alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("account login status = %d", rr.Code)
	}
	legacy, appErr := s.createAppLoginSession("Legacy Desktop", time.Hour)
	if appErr != nil {
		t.Fatalf("legacy App login failed: %s", appErr.message)
	}
	accountToken := account["accessToken"].(string)
	for _, token := range []string{legacy.AccessToken, accountToken} {
		for _, path := range []string{"/api/openid/userinfo", "/openid/userinfo"} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				if rr := accountRequest(t, s.Handler(), method, path, token, nil); rr.Code != http.StatusUnauthorized {
					t.Errorf("%s %s accepted App token: status = %d", method, path, rr.Code)
				}
			}
		}
	}
	if rr := accountRequest(t, s.Handler(), http.MethodPost, "/api/auth/logout", accountToken, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("account logout status = %d", rr.Code)
	}
	if rr := accountRequest(t, s.Handler(), http.MethodGet, "/api/openid/userinfo", accountToken, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC accepted logged-out account token: status = %d", rr.Code)
	}
	if rr := accountRequest(t, s.Handler(), http.MethodGet, "/api/auth/me", legacy.AccessToken, nil); rr.Code != http.StatusOK {
		t.Fatalf("account logout affected legacy App token: status = %d", rr.Code)
	}
}

func TestOIDCUserInfoAcceptsOAuthAccessToken(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	s.cfg.TokenAccessTTL = time.Hour
	id := createAccountUser(t, s, "alice")
	user, err := s.store.FindUserByID(id)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := s.issueOAuthAccessToken(user, "desktop-sso", []string{"openid", "profile"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/openid/userinfo", "/openid/userinfo"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rr := accountRequest(t, s.Handler(), method, path, token, nil)
			if rr.Code != http.StatusOK {
				t.Fatalf("%s %s rejected OAuth token: status = %d", method, path, rr.Code)
			}
			body := decodeBody(t, rr)
			if body["sub"] != id || body["preferred_username"] != user.Username || body["scope"] != "openid profile" {
				t.Fatalf("OAuth userinfo changed: %v", body)
			}
		}
	}
}

func TestOAuthTokenRequiresAudienceAndClientIdentity(t *testing.T) {
	s, cleanup := newAppAccessTestServer(t)
	defer cleanup()
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		audience any
		clientID any
		valid    bool
	}{
		{"string audience", "app-api", "desktop-sso", true},
		{"array audience", []string{"other", "app-api"}, "desktop-sso", true},
		{"wrong audience", []string{"app", "tunnel"}, "desktop-sso", false},
		{"missing audience", nil, "desktop-sso", false},
		{"missing client", "app-api", nil, false},
		{"blank client", "app-api", " ", false},
		{"non-string client", "app-api", 123, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := security.SignJWT(key, map[string]any{
				"iss": s.cfg.Issuer, "sub": "test-user", "scope": "openid profile",
				"exp": time.Now().Add(time.Hour).Unix(), "aud": test.audience, "client_id": test.clientID,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.verifyOAuthAccessToken(token)
			if (err == nil) != test.valid {
				t.Fatalf("valid = %v, want %v", err == nil, test.valid)
			}
		})
	}
}
