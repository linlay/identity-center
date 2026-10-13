package model

import "time"

type AppPrincipal struct {
	Username  string
	AccountID string
	DeviceID  string
	IssuedAt  time.Time
}

type AdminSession struct {
	SessionID string
	Username  string
	IssuedAt  time.Time
}

type OAuthUserSession struct {
	SessionID string
	Username  string
	IssuedAt  time.Time
}

type OAuthCode struct {
	ID            string
	ClientID      string
	Username      string
	Scopes        string
	RedirectURI   string
	Code          string
	CodeExpiresAt time.Time
	CodeIssuedAt  time.Time
}

type OAuthTokens struct {
	AuthorizationID  string
	ClientID         string
	Username         string
	Scopes           string
	AccessToken      string
	AccessIssuedAt   time.Time
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshIssuedAt  time.Time
	RefreshExpiresAt time.Time
}
