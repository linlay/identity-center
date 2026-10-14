package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"

	"identity-center/backend/internal/config"
	"identity-center/backend/internal/model"
	"identity-center/backend/internal/security"
	"identity-center/backend/internal/store"
)

const (
	adminSessionCookieName     = "ADMIN_SESSION"
	oauthUserSessionCookieName = "OAUTH_USER_SESSION"
	adminAPIBasePath           = "/admin/api"
	canonicalOpenIDBasePath    = "/api/openid"
	canonicalOAuth2BasePath    = "/api/oauth2"
	legacyOpenIDBasePath       = "/openid"
	legacyOAuth2BasePath       = "/oauth2"
	accountLoginChallengeTTL   = 2 * time.Minute
)

//go:embed templates/*.html
var templatesFS embed.FS

type Server struct {
	cfg       *config.Config
	store     *store.Store
	keys      *security.KeyManager
	router    http.Handler
	templates *template.Template
	logger    *log.Logger

	adminSessionsMu sync.RWMutex
	adminSessions   map[string]model.AdminSession

	oauthSessionsMu sync.RWMutex
	oauthSessions   map[string]model.OAuthUserSession

	sendEmail func(context.Context, string, string, string) error
	cron      *cron.Cron
}

type contextKey string

const (
	ctxAdminSessionKey contextKey = "admin_session"
	ctxAppPrincipalKey contextKey = "app_principal"
)

func New(cfg *config.Config, st *store.Store, keys *security.KeyManager, logger *log.Logger) (*Server, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:           cfg,
		store:         st,
		keys:          keys,
		templates:     tmpl,
		logger:        logger,
		adminSessions: map[string]model.AdminSession{},
		oauthSessions: map[string]model.OAuthUserSession{},
	}
	s.sendEmail = func(ctx context.Context, email, purpose, code string) error {
		return sendAccountEmail(ctx, cfg.Email, email, purpose, code)
	}
	s.router = s.routes()

	c := cron.New(cron.WithSeconds())
	_, err = c.AddFunc(cfg.CleanupCron, func() {
		if _, err := s.store.DeleteRevokedDevicesOlderThan(cfg.CleanupRetention); err != nil {
			s.logger.Printf("cleanup devices failed: %v", err)
		}
		if _, err := s.store.DeleteTokenAuditIssuedOlderThan(cfg.CleanupRetention); err != nil {
			s.logger.Printf("cleanup token audit failed: %v", err)
		}
		if err := s.store.CleanupEmailAuth(time.Now().UTC()); err != nil {
			s.logger.Print("cleanup email auth failed")
		}
		if _, err := s.store.DeleteExpiredLoginChallengesOlderThan(cfg.CleanupRetention); err != nil {
			s.logger.Printf("cleanup login challenges failed: %v", err)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("invalid cleanup cron: %w", err)
	}
	s.cron = c
	s.cron.Start()

	if err := s.store.EnsureBootstrapClient(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() {
	if s.cron != nil {
		s.cron.Stop()
	}
}

func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.rememberEmailPeer)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.NoCache)
	r.Use(s.cors)

	s.mountOpenIDRoutes(r, canonicalOpenIDBasePath)
	s.mountOpenIDRoutes(r, legacyOpenIDBasePath)
	s.mountOAuth2Routes(r, canonicalOAuth2BasePath)
	s.mountOAuth2Routes(r, legacyOAuth2BasePath)

	r.Route(adminAPIBasePath, func(ar chi.Router) {
		ar.Post("/session/login", s.handleAdminLogin)
		ar.Post("/bcrypt/generate", s.handleBcryptGenerate)

		ar.Group(func(pr chi.Router) {
			pr.Use(s.adminAPIMiddleware)
			pr.Post("/session/logout", s.handleAdminLogout)
			pr.Get("/session/me", s.handleAdminMe)

			pr.Get("/users", s.handleListUsers)
			pr.Post("/users", s.handleCreateUser)
			pr.Get("/users/{userId}", s.handleGetUser)
			pr.Put("/users/{userId}", s.handleUpdateUser)
			pr.Patch("/users/{userId}/status", s.handlePatchUserStatus)
			pr.Post("/users/{userId}/password", s.handleResetUserPassword)
			pr.Post("/users/{userId}/email/unbind", s.handleAdminUnbindEmail)

			pr.Get("/clients", s.handleListClients)
			pr.Post("/clients", s.handleCreateClient)
			pr.Get("/clients/{clientId}", s.handleGetClient)
			pr.Put("/clients/{clientId}", s.handleUpdateClient)
			pr.Patch("/clients/{clientId}/status", s.handlePatchClientStatus)
			pr.Post("/clients/{clientId}/secret/rotate", s.handleRotateClientSecret)
			pr.Post("/security/app-tokens/issue", s.handleAdminIssueAppToken)
			pr.Post("/security/app-tokens/refresh", s.handleAdminRefreshAppToken)
			pr.Get("/security/app-devices", s.handleAdminListAppDevices)
			pr.Post("/security/app-devices/{deviceId}/revoke", s.handleAdminRevokeAppDevice)
			pr.Get("/security/jwks", s.handleAdminSecurityJWKS)
			pr.Post("/security/public-key/generate", s.handleAdminGeneratePublicKey)
			pr.Post("/security/key-pair/generate", s.handleAdminGenerateKeyPair)
			pr.Get("/security/key-pair/export", s.handleAdminExportKeyPair)
			pr.Get("/security/tokens", s.handleAdminListTokenAudits)
		})
	})

	r.Route("/api", func(api chi.Router) {
		api.Route("/auth", func(ar chi.Router) {
			ar.Post("/account/login", s.handleAccountAppLogin)
			ar.Post("/account/email/challenges", s.handleEmailLoginChallenge)
			ar.Post("/account/email/login", s.handleEmailLogin)
			ar.Post("/account/login-challenges", s.handleStartAccountLoginChallenge)
			ar.Post("/account/login-challenges/{challengeId}/claim", s.handleClaimAccountLoginChallenge)
			ar.Post("/refresh", s.handleAppRefresh)
			ar.Get("/jwks", s.handleAppJWKS)

			ar.Group(func(g chi.Router) {
				g.Use(s.appBearerMiddleware)
				g.Post("/account/login-challenges/{challengeId}/confirm", s.handleConfirmAccountLoginChallenge)
				g.Get("/account/security", s.handleAccountSecurity)
				g.Post("/account/email/bind/challenges", s.handleEmailBindChallenge)
				g.Post("/account/email/bind", s.handleEmailBind)
				g.Post("/account/email/unbind/challenges", s.handleEmailUnbindChallenge)
				g.Post("/account/email/unbind", s.handleEmailUnbind)
				g.Post("/logout", s.handleAppLogout)
				g.Get("/me", s.handleAppMe)
				g.Get("/devices", s.handleAppDevices)
				g.Patch("/devices/{deviceId}", s.handleAppRenameDevice)
				g.Delete("/devices/{deviceId}", s.handleAppDeleteDevice)
			})
		})
	})

	return r
}

func (s *Server) mountOpenIDRoutes(r chi.Router, prefix string) {
	r.Route(prefix, func(or chi.Router) {
		or.Get("/login", s.handleOpenIDLoginPage)
		or.Post("/login", s.handleOpenIDLoginSubmit)
		or.Get("/consent", s.handleOpenIDConsentPage)
		or.Post("/consent", s.handleOpenIDConsentSubmit)
		or.Get("/.well-known/openid-configuration", s.handleOpenIDConfiguration)
		or.Get("/.well-known/oauth-authorization-server", s.handleOAuthMetadata)
		or.Get("/jwks", s.handleOpenIDJWKS)
		or.Get("/userinfo", s.handleOpenIDUserInfo)
		or.Post("/userinfo", s.handleOpenIDUserInfo)
	})
}

func (s *Server) mountOAuth2Routes(r chi.Router, prefix string) {
	r.Route(prefix, func(or chi.Router) {
		or.Get("/authorize", s.handleOAuthAuthorize)
		or.Post("/token", s.handleOAuthToken)
		or.Post("/revoke", s.handleOAuthRevoke)
		or.Post("/introspect", s.handleOAuthIntrospect)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		if w.Header().Get("Access-Control-Allow-Origin") == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Expose-Headers", "Set-Cookie")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminAPIMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(adminSessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.adminSessionsMu.RLock()
		session, ok := s.adminSessions[cookie.Value]
		s.adminSessionsMu.RUnlock()
		if !ok || time.Since(session.IssuedAt) > 8*time.Hour {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAdminSessionKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) appBearerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		principal, err := s.authenticateAppAccessToken(token)
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAppPrincipalKey, *principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) currentAdminSession(r *http.Request) (model.AdminSession, bool) {
	sess, ok := r.Context().Value(ctxAdminSessionKey).(model.AdminSession)
	return sess, ok
}

func (s *Server) currentAppPrincipal(r *http.Request) (model.AppPrincipal, bool) {
	principal, ok := r.Context().Value(ctxAppPrincipalKey).(model.AppPrincipal)
	return principal, ok
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	normalizedUsername := strings.TrimSpace(req.Username)
	normalizedPassword := strings.TrimSpace(req.Password)
	if normalizedUsername == "" || normalizedPassword == "" {
		writeAPIError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	usernameMatched := normalizedUsername == s.cfg.AdminUsername
	passwordMatched := bcrypt.CompareHashAndPassword([]byte(s.cfg.AdminPasswordBcrypt), []byte(req.Password)) == nil
	if !usernameMatched || !passwordMatched {
		if s.logger != nil {
			s.logger.Printf(
				"admin login failed: remote=%s username_match=%t password_match=%t requested_username=%q",
				r.RemoteAddr,
				usernameMatched,
				passwordMatched,
				normalizedUsername,
			)
		}
		writeAPIError(w, http.StatusBadRequest, "invalid admin credentials")
		return
	}
	sessionID := uuid.NewString()
	now := time.Now().UTC()
	session := model.AdminSession{SessionID: sessionID, Username: s.cfg.AdminUsername, IssuedAt: now}
	s.adminSessionsMu.Lock()
	s.adminSessions[sessionID] = session
	s.adminSessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   8 * 60 * 60,
	})
	writeJSON(w, http.StatusOK, map[string]any{"username": session.Username, "issuedAt": session.IssuedAt})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if session, ok := s.currentAdminSession(r); ok {
		s.adminSessionsMu.Lock()
		delete(s.adminSessions, session.SessionID)
		s.adminSessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 0})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminMe(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentAdminSession(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": session.Username, "issuedAt": session.IssuedAt})
}

func (s *Server) handleBcryptGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		writeAPIError(w, http.StatusBadRequest, "password is required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "failed to generate bcrypt")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bcrypt": string(hash)})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
		Status      string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" || strings.TrimSpace(req.DisplayName) == "" {
		writeAPIError(w, http.StatusBadRequest, "username, password and displayName are required")
		return
	}
	status := normalizeStatus(req.Status)
	if status == "" {
		writeAPIError(w, http.StatusBadRequest, "status must be ACTIVE or DISABLED")
		return
	}
	user, err := s.store.CreateUser(req.Username, req.Password, req.DisplayName, status)
	if err != nil {
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.FindUserByID(chi.URLParam(r, "userId"))
	if err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusBadRequest, "user not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName string `json:"displayName"`
		Status      string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		writeAPIError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	status := normalizeStatus(req.Status)
	if status == "" {
		writeAPIError(w, http.StatusBadRequest, "status must be ACTIVE or DISABLED")
		return
	}
	user, err := s.store.UpdateUser(chi.URLParam(r, "userId"), req.DisplayName, status)
	if err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusBadRequest, "user not found")
			return
		}
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handlePatchUserStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	status := normalizeStatus(req.Status)
	if status == "" {
		writeAPIError(w, http.StatusBadRequest, "status must be ACTIVE or DISABLED")
		return
	}
	user, err := s.store.PatchUserStatus(chi.URLParam(r, "userId"), status)
	if err != nil {
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		writeAPIError(w, http.StatusBadRequest, "password is required")
		return
	}
	if err := s.store.ResetUserPassword(chi.URLParam(r, "userId"), req.Password); err != nil {
		writeSQLError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string   `json:"clientId"`
		ClientName   string   `json:"clientName"`
		ClientSecret string   `json:"clientSecret"`
		GrantTypes   []string `json:"grantTypes"`
		RedirectURIs []string `json:"redirectUris"`
		Scopes       []string `json:"scopes"`
		RequirePKCE  *bool    `json:"requirePkce"`
		Status       string   `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.ClientName) == "" || len(req.GrantTypes) == 0 || len(req.Scopes) == 0 {
		writeAPIError(w, http.StatusBadRequest, "clientId, clientName, grantTypes and scopes are required")
		return
	}
	if contains(req.GrantTypes, "authorization_code") && req.RequirePKCE != nil && !*req.RequirePKCE {
		writeAPIError(w, http.StatusBadRequest, "authorization_code clients must enable PKCE")
		return
	}
	status := normalizeStatusOrDefault(req.Status)
	client, err := s.store.CreateClient(store.OAuthClientCreateRequest{
		ClientID:           req.ClientID,
		ClientName:         req.ClientName,
		ClientSecret:       req.ClientSecret,
		GrantTypes:         req.GrantTypes,
		RedirectURIs:       req.RedirectURIs,
		Scopes:             req.Scopes,
		RequirePKCE:        req.RequirePKCE,
		Status:             status,
		RotateRefreshToken: s.cfg.TokenRotateRefresh,
	})
	if err != nil {
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, client)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	client, err := s.store.FindClient(chi.URLParam(r, "clientId"))
	if err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusBadRequest, "client not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName   string   `json:"clientName"`
		GrantTypes   []string `json:"grantTypes"`
		RedirectURIs []string `json:"redirectUris"`
		Scopes       []string `json:"scopes"`
		RequirePKCE  *bool    `json:"requirePkce"`
		Status       string   `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ClientName) == "" || len(req.Scopes) == 0 {
		writeAPIError(w, http.StatusBadRequest, "clientName and scopes are required")
		return
	}
	clientID := chi.URLParam(r, "clientId")
	current, err := s.store.FindClient(clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusBadRequest, "client not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = current.GrantTypes
	}
	requirePkce := current.RequirePKCE
	if req.RequirePKCE != nil {
		requirePkce = *req.RequirePKCE
	}
	if contains(grantTypes, "authorization_code") && !requirePkce {
		writeAPIError(w, http.StatusBadRequest, "authorization_code clients must enable PKCE")
		return
	}
	status := normalizeStatusOrDefault(req.Status)
	updated, err := s.store.UpdateClient(clientID, store.OAuthClientUpdateRequest{
		ClientName:   req.ClientName,
		GrantTypes:   grantTypes,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		RequirePKCE:  requirePkce,
		Status:       status,
	})
	if err != nil {
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handlePatchClientStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	status := normalizeStatus(req.Status)
	if status == "" {
		writeAPIError(w, http.StatusBadRequest, "status must be ACTIVE or DISABLED")
		return
	}
	updated, err := s.store.PatchClientStatus(chi.URLParam(r, "clientId"), status)
	if err != nil {
		writeSQLError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	if _, err := s.store.FindClient(clientID); err != nil {
		writeAPIError(w, http.StatusBadRequest, "client not found")
		return
	}
	secret, err := s.store.RotateClientSecret(clientID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clientId": clientID, "newClientSecret": secret})
}

func (s *Server) handleAdminIssueAppToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceName       string `json:"deviceName"`
		AccessTTLSeconds *int   `json:"accessTtlSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	accessTTL, err := s.resolveAccessTTL(req.AccessTTLSeconds)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, appErr := s.createAppLoginSession(req.DeviceName, accessTTL)
	if appErr != nil {
		writeAPIError(w, appErr.status, appErr.message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAccountAppLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		DeviceName string `json:"deviceName"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !store.ValidAccountSessionName(req.DeviceName) {
		writeAPIError(w, http.StatusBadRequest, "deviceName must contain 1-64 characters")
		return
	}
	username := strings.TrimSpace(req.Username)
	user, err := s.store.FindUserByUsername(username)
	if err != nil || user.Status != "ACTIVE" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	accessTTL, err := s.resolveAccessTTL(nil)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	result, err := s.createAccountAppLoginSession(user, req.DeviceName, accessTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type accountAppLoginResult struct {
	SchemaVersion       int       `json:"schemaVersion"`
	AccountID           string    `json:"accountId"`
	Username            string    `json:"username"`
	DeviceID            string    `json:"deviceId"`
	DeviceName          string    `json:"deviceName"`
	AccessToken         string    `json:"accessToken"`
	AccessTokenExpireAt time.Time `json:"accessTokenExpireAt"`
	DeviceToken         string    `json:"deviceToken,omitempty"`
}

func (s *Server) createAccountAppLoginSession(user *store.User, deviceName string, accessTTL time.Duration) (*accountAppLoginResult, error) {
	created, err := s.store.CreateAccountSession(user.UserID, deviceName)
	if err != nil {
		return nil, err
	}
	return s.finishAccountAppLoginSession(user, created, accessTTL)
}

func (s *Server) finishAccountAppLoginSession(user *store.User, created store.CreateAccountSessionResult, accessTTL time.Duration) (*accountAppLoginResult, error) {
	accessToken, issuedAt, expiresAt, err := s.issueAccountAppAccessToken(user, created.Session, accessTTL)
	if err != nil {
		_ = s.store.RevokeAccountSession(user.UserID, created.Session.DeviceID)
		return nil, err
	}
	username := user.Username
	deviceID := created.Session.DeviceID
	deviceName := created.Session.DeviceName
	if err := s.store.RecordTokenAudit("ACCOUNT_APP_ACCESS", accessToken, &username, &deviceID, &deviceName, nil, nil, issuedAt, &expiresAt); err != nil {
		s.logger.Printf("record account app token audit failed: %v", err)
	}
	result := &accountAppLoginResult{
		SchemaVersion:       1,
		AccountID:           user.UserID,
		Username:            user.Username,
		DeviceID:            created.Session.DeviceID,
		DeviceName:          created.Session.DeviceName,
		AccessToken:         accessToken,
		AccessTokenExpireAt: expiresAt,
	}
	result.DeviceToken = created.DeviceToken
	return result, nil
}

func (s *Server) handleStartAccountLoginChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceName string `json:"deviceName"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !store.ValidAccountSessionName(req.DeviceName) {
		writeAPIError(w, http.StatusBadRequest, "deviceName must contain 1-64 characters")
		return
	}
	created, err := s.store.CreateLoginChallenge(req.DeviceName, time.Now().UTC(), accountLoginChallengeTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"schemaVersion": 1,
		"challengeId":   created.Challenge.ChallengeID,
		"claimToken":    created.ClaimToken,
		"qrPayload":     map[string]string{"challengeId": created.Challenge.ChallengeID},
		"expiresAt":     created.Challenge.ExpiresAt,
	})
}

func (s *Server) handleConfirmAccountLoginChallenge(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAccountPrincipal(w, r)
	if !ok {
		return
	}
	challenge, err := s.store.ConfirmLoginChallenge(
		chi.URLParam(r, "challengeId"), principal.AccountID, principal.DeviceID,
		time.Now().UTC(),
	)
	if err != nil {
		writeLoginChallengeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": 1,
		"challengeId":   challenge.ChallengeID,
		"status":        "confirmed",
		"confirmedAt":   challenge.ConfirmedAt,
	})
}

func (s *Server) handleClaimAccountLoginChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClaimToken string `json:"claimToken"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	challenge, err := s.store.ClaimLoginChallenge(chi.URLParam(r, "challengeId"), req.ClaimToken, time.Now().UTC())
	if err != nil {
		writeLoginChallengeError(w, err)
		return
	}
	user, err := s.store.FindUserByID(challenge.AccountID)
	if err != nil || user.Status != "ACTIVE" {
		writeAPIError(w, http.StatusUnauthorized, "account unavailable")
		return
	}
	accessTTL, err := s.resolveAccessTTL(nil)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	result, err := s.createAccountAppLoginSession(
		user, challenge.TargetDeviceName, accessTTL,
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) currentAccountPrincipal(w http.ResponseWriter, r *http.Request) (model.AppPrincipal, bool) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok || principal.AccountID == "" {
		writeAPIError(w, http.StatusUnauthorized, "account session required")
		return model.AppPrincipal{}, false
	}
	return principal, true
}

func writeLoginChallengeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLoginChallengeNotFound):
		writeAPIError(w, http.StatusNotFound, "login challenge not found")
	case errors.Is(err, store.ErrLoginChallengeExpired):
		writeAPIError(w, http.StatusGone, "login challenge expired")
	case errors.Is(err, store.ErrLoginChallengeNotReady):
		writeAPIError(w, http.StatusConflict, "login challenge not confirmed")
	case errors.Is(err, store.ErrLoginChallengeConfirmer):
		writeAPIError(w, http.StatusForbidden, "confirming session is inactive")
	case errors.Is(err, store.ErrLoginChallengeToken):
		writeAPIError(w, http.StatusUnauthorized, "invalid login challenge token")
	case errors.Is(err, store.ErrLoginChallengeConsumed):
		writeAPIError(w, http.StatusConflict, "login challenge already consumed")
	default:
		writeInternalError(w, err)
	}
}

type appLoginResult struct {
	Username            string    `json:"username"`
	DeviceID            string    `json:"deviceId"`
	DeviceName          string    `json:"deviceName"`
	AccessToken         string    `json:"accessToken"`
	AccessTokenExpireAt time.Time `json:"accessTokenExpireAt"`
	DeviceToken         string    `json:"deviceToken"`
}

type appError struct {
	status  int
	message string
}

func (s *Server) createAppLoginSession(deviceName string, accessTTL time.Duration) (*appLoginResult, *appError) {
	deviceToken, err := randomToken(32)
	if err != nil {
		return nil, &appError{status: http.StatusInternalServerError, message: "failed to generate token"}
	}
	device, err := s.store.CreateDevice(deviceName, deviceToken)
	if err != nil {
		return nil, &appError{status: http.StatusInternalServerError, message: "failed to create device"}
	}
	accessToken, issuedAt, expAt, err := s.issueAppAccessToken(s.cfg.AppUsername, device.DeviceID, accessTTL)
	if err != nil {
		return nil, &appError{status: http.StatusInternalServerError, message: "failed to issue access token"}
	}
	username := s.cfg.AppUsername
	deviceID := device.DeviceID
	auditDeviceName := device.DeviceName
	if err := s.store.RecordTokenAudit("APP_ACCESS", accessToken, &username, &deviceID, &auditDeviceName, nil, nil, issuedAt, &expAt); err != nil {
		s.logger.Printf("record app token audit failed: %v", err)
	}
	return &appLoginResult{
		Username:            s.cfg.AppUsername,
		DeviceID:            device.DeviceID,
		DeviceName:          device.DeviceName,
		AccessToken:         accessToken,
		AccessTokenExpireAt: expAt,
		DeviceToken:         deviceToken,
	}, nil
}

func (s *Server) handleAppRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceToken      string `json:"deviceToken"`
		AccessTTLSeconds *int   `json:"accessTtlSeconds"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	accessTTL, err := s.resolveAccessTTL(req.AccessTTLSeconds)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.Contains(strings.TrimSpace(req.DeviceToken), ".") {
		s.handleAccountAppRefresh(w, req.DeviceToken, accessTTL)
		return
	}
	device, err := s.store.FindActiveDeviceByToken(req.DeviceToken)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid device token")
		return
	}
	nextDeviceToken := req.DeviceToken
	if s.cfg.AppRotateDeviceToken {
		nextDeviceToken, err = randomToken(32)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		if err := s.store.RotateDeviceToken(device.DeviceID, nextDeviceToken); err != nil {
			writeInternalError(w, err)
			return
		}
	} else {
		_ = s.store.TouchDevice(device.DeviceID)
	}
	updatedDevice, _ := s.store.FindDeviceByID(device.DeviceID)
	if updatedDevice == nil {
		updatedDevice = device
	}
	accessToken, issuedAt, expAt, err := s.issueAppAccessToken(s.cfg.AppUsername, updatedDevice.DeviceID, accessTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	username := s.cfg.AppUsername
	deviceID := updatedDevice.DeviceID
	deviceName := updatedDevice.DeviceName
	_ = s.store.RecordTokenAudit("APP_ACCESS", accessToken, &username, &deviceID, &deviceName, nil, nil, issuedAt, &expAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":            updatedDevice.DeviceID,
		"accessToken":         accessToken,
		"accessTokenExpireAt": expAt,
		"deviceToken":         nextDeviceToken,
	})
}

func (s *Server) handleAccountAppRefresh(w http.ResponseWriter, deviceToken string, accessTTL time.Duration) {
	device, err := s.store.FindActiveAccountSessionByToken(deviceToken)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid device token")
		return
	}
	user, err := s.store.FindUserByID(device.AccountID)
	if err != nil || user.Status != "ACTIVE" {
		writeAPIError(w, http.StatusUnauthorized, "invalid device token")
		return
	}
	accessToken, issuedAt, expiresAt, err := s.issueAccountAppAccessToken(user, *device, accessTTL)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	nextDeviceToken := deviceToken
	if s.cfg.AppRotateDeviceToken {
		nextDeviceToken, err = s.store.RotateAccountSessionCredential(device.AccountID, device.DeviceID, device.DeviceTokenBcrypt)
	} else {
		err = s.store.TouchAccountSession(device.AccountID, device.DeviceID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusUnauthorized, "invalid device token")
			return
		}
		writeInternalError(w, err)
		return
	}
	username := user.Username
	deviceID := device.DeviceID
	deviceName := device.DeviceName
	if err := s.store.RecordTokenAudit("ACCOUNT_APP_ACCESS", accessToken, &username, &deviceID, &deviceName, nil, nil, issuedAt, &expiresAt); err != nil {
		s.logger.Printf("record account app token audit failed: %v", err)
	}
	writeJSON(w, http.StatusOK, accountAppLoginResult{
		SchemaVersion:       1,
		AccountID:           device.AccountID,
		Username:            user.Username,
		DeviceID:            device.DeviceID,
		DeviceName:          device.DeviceName,
		AccessToken:         accessToken,
		AccessTokenExpireAt: expiresAt,
		DeviceToken:         nextDeviceToken,
	})
}

func (s *Server) handleAdminRefreshAppToken(w http.ResponseWriter, r *http.Request) {
	s.handleAppRefresh(w, r)
}

func (s *Server) handleAppLogout(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var err error
	if principal.AccountID != "" {
		err = s.store.RevokeAccountSession(principal.AccountID, principal.DeviceID)
	} else {
		err = s.store.RevokeDevice(principal.DeviceID)
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_ = s.store.MarkTokensRevokedByDeviceID(principal.DeviceID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAppMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": 1,
		"username":      principal.Username,
		"accountId":     principal.AccountID,
		"deviceId":      principal.DeviceID,
		"issuedAt":      principal.IssuedAt,
	})
}

func (s *Server) handleAppDevices(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok || principal.AccountID != "" {
		writeAPIError(w, http.StatusForbidden, "legacy app session required")
		return
	}
	devices, err := s.store.ListDevices()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleAppRenameDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok || principal.AccountID != "" {
		writeAPIError(w, http.StatusForbidden, "legacy app session required")
		return
	}
	deviceID := chi.URLParam(r, "deviceId")
	if _, err := uuid.Parse(deviceID); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var req struct {
		DeviceName string `json:"deviceName"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DeviceName) == "" {
		writeAPIError(w, http.StatusBadRequest, "deviceName is required")
		return
	}
	if err := s.store.RenameDevice(deviceID, req.DeviceName); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	device, err := s.store.FindDeviceByID(deviceID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) handleAppDeleteDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAppPrincipal(r)
	if !ok || principal.AccountID != "" {
		writeAPIError(w, http.StatusForbidden, "legacy app session required")
		return
	}
	deviceID := chi.URLParam(r, "deviceId")
	_ = s.store.RevokeDevice(deviceID)
	_ = s.store.MarkTokensRevokedByDeviceID(deviceID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAppJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.keys.PublicJWKSet()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jwks)
}

func (s *Server) handleAdminSecurityJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.keys.PublicJWKSet()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jwks": jwks})
}

func (s *Server) handleAdminListAppDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListDevices()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleAdminRevokeAppDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")
	_ = s.store.RevokeDevice(deviceID)
	_ = s.store.MarkTokensRevokedByDeviceID(deviceID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminGeneratePublicKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		E string `json:"e"`
		N string `json:"n"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	pemValue, err := s.keys.PublicKeyPEMFromJWK(req.E, req.N)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pemValue})
}

func (s *Server) handleAdminGenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	pub, priv, err := security.GenerateEphemeralRSAKeyPair()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pub, "privateKey": priv})
}

func (s *Server) handleAdminExportKeyPair(w http.ResponseWriter, r *http.Request) {
	pub, priv, err := s.keys.ExportKeyPairPEM()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pub, "privateKey": priv})
}

func (s *Server) handleAdminListTokenAudits(w http.ResponseWriter, r *http.Request) {
	sources := splitCSVQuery(r.URL.Query().Get("sources"))
	if len(sources) == 0 {
		sources = []string{"APP_ACCESS", "OAUTH_ACCESS", "OAUTH_REFRESH"}
	}
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if status == "" {
		status = "ALL"
	}
	limit := parseIntDefault(r.URL.Query().Get("limit"), 200)
	records, err := s.store.ListTokenAudits(sources, status, limit)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		state := "ACTIVE"
		if rec.RevokedAt != nil {
			state = "REVOKED"
		} else if rec.ExpiresAt != nil && !rec.ExpiresAt.After(time.Now().UTC()) {
			state = "EXPIRED"
		}
		payload = append(payload, map[string]any{
			"tokenId":         rec.TokenID,
			"source":          rec.Source,
			"token":           rec.Token,
			"tokenSha256":     rec.TokenSHA256,
			"username":        rec.Username,
			"deviceId":        rec.DeviceID,
			"deviceName":      rec.DeviceName,
			"clientId":        rec.ClientID,
			"authorizationId": rec.AuthorizationID,
			"issuedAt":        rec.IssuedAt,
			"expiresAt":       rec.ExpiresAt,
			"revokedAt":       rec.RevokedAt,
			"status":          state,
		})
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + canonicalOAuth2BasePath + "/authorize",
		"token_endpoint":                        issuer + canonicalOAuth2BasePath + "/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"jwks_uri":                              issuer + canonicalOpenIDBasePath + "/jwks",
		"userinfo_endpoint":                     issuer + canonicalOpenIDBasePath + "/userinfo",
		"revocation_endpoint":                   issuer + canonicalOAuth2BasePath + "/revoke",
		"introspection_endpoint":                issuer + canonicalOAuth2BasePath + "/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile"},
		"claims_supported":                      []string{"sub", "preferred_username", "display_name", "scope"},
	})
}

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                   issuer,
		"authorization_endpoint":   issuer + canonicalOAuth2BasePath + "/authorize",
		"token_endpoint":           issuer + canonicalOAuth2BasePath + "/token",
		"jwks_uri":                 issuer + canonicalOpenIDBasePath + "/jwks",
		"revocation_endpoint":      issuer + canonicalOAuth2BasePath + "/revoke",
		"introspection_endpoint":   issuer + canonicalOAuth2BasePath + "/introspect",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
	})
}

func (s *Server) handleOpenIDJWKS(w http.ResponseWriter, r *http.Request) {
	s.handleAppJWKS(w, r)
}

func (s *Server) handleOpenIDUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	claims, err := s.verifyOAuthAccessToken(token)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                claims["sub"],
		"preferred_username": claims["preferred_username"],
		"display_name":       claims["display_name"],
		"scope":              claims["scope"],
	})
}

func (s *Server) handleOpenIDLoginPage(w http.ResponseWriter, r *http.Request) {
	next := strings.TrimSpace(r.URL.Query().Get("next"))
	if next == "" {
		next = canonicalOAuth2BasePath + "/authorize"
	}
	data := map[string]any{
		"Next":  next,
		"Error": r.URL.Query().Get("error") != "",
	}
	if err := s.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) handleOpenIDLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, canonicalOpenIDBasePath+"/login?error=1", http.StatusFound)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := strings.TrimSpace(r.FormValue("next"))
	if next == "" {
		next = canonicalOAuth2BasePath + "/authorize"
	}
	user, err := s.store.FindUserByUsername(username)
	if err != nil || user.Status != "ACTIVE" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		http.Redirect(w, r, canonicalOpenIDBasePath+"/login?error=1&next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	sessionID := uuid.NewString()
	s.oauthSessionsMu.Lock()
	s.oauthSessions[sessionID] = model.OAuthUserSession{SessionID: sessionID, Username: username, IssuedAt: time.Now().UTC()}
	s.oauthSessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: oauthUserSessionCookieName, Value: sessionID, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/", MaxAge: 8 * 3600})
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) handleOpenIDConsentPage(w http.ResponseWriter, r *http.Request) {
	oauthUser, ok := s.currentOAuthUser(r)
	if !ok {
		http.Redirect(w, r, canonicalOpenIDBasePath+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	state := r.URL.Query().Get("state")
	scopeParam := strings.TrimSpace(r.URL.Query().Get("scope"))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	challengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	client, err := s.store.FindActiveClient(clientID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "client not found")
		return
	}
	scopes := splitScopes(scopeParam)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	sort.Strings(scopes)
	data := map[string]any{
		"principalName":       oauthUser.Username,
		"clientId":            clientID,
		"clientName":          client.ClientName,
		"state":               state,
		"scopes":              scopes,
		"redirectUri":         redirectURI,
		"codeChallenge":       codeChallenge,
		"codeChallengeMethod": challengeMethod,
	}
	if err := s.templates.ExecuteTemplate(w, "consent.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) handleOpenIDConsentSubmit(w http.ResponseWriter, r *http.Request) {
	oauthUser, ok := s.currentOAuthUser(r)
	if !ok {
		http.Redirect(w, r, canonicalOpenIDBasePath+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid consent request")
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	state := strings.TrimSpace(r.FormValue("state"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	codeChallenge := strings.TrimSpace(r.FormValue("code_challenge"))
	challengeMethod := strings.TrimSpace(r.FormValue("code_challenge_method"))
	action := strings.TrimSpace(r.FormValue("consent_action"))
	scopes := r.Form["scope"]
	if action == "deny" {
		dest, _ := url.Parse(redirectURI)
		q := dest.Query()
		q.Set("error", "access_denied")
		if state != "" {
			q.Set("state", state)
		}
		dest.RawQuery = q.Encode()
		http.Redirect(w, r, dest.String(), http.StatusFound)
		return
	}
	if len(scopes) == 0 {
		writeAPIError(w, http.StatusBadRequest, "scope is required")
		return
	}
	if err := s.store.SaveOAuthConsent(clientID, oauthUser.Username, scopes); err != nil {
		writeInternalError(w, err)
		return
	}
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("state", state)
	query.Set("scope", strings.Join(scopes, " "))
	if redirectURI != "" {
		query.Set("redirect_uri", redirectURI)
	}
	if codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
	}
	if challengeMethod != "" {
		query.Set("code_challenge_method", challengeMethod)
	}
	http.Redirect(w, r, canonicalOAuth2BasePath+"/authorize?"+query.Encode(), http.StatusFound)
}

func (s *Server) currentOAuthUser(r *http.Request) (model.OAuthUserSession, bool) {
	cookie, err := r.Cookie(oauthUserSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return model.OAuthUserSession{}, false
	}
	s.oauthSessionsMu.RLock()
	session, ok := s.oauthSessions[cookie.Value]
	s.oauthSessionsMu.RUnlock()
	if !ok || time.Since(session.IssuedAt) > 8*time.Hour {
		return model.OAuthUserSession{}, false
	}
	return session, true
}

func (s *Server) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.URL.Query().Get("response_type")) != "code" {
		writeAPIError(w, http.StatusBadRequest, "unsupported response_type")
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	scopeParam := strings.TrimSpace(r.URL.Query().Get("scope"))
	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	challengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	if challengeMethod == "" {
		challengeMethod = "plain"
	}

	client, err := s.store.FindActiveClient(clientID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "client not found")
		return
	}
	if !contains(client.GrantTypes, "authorization_code") {
		writeAPIError(w, http.StatusBadRequest, "client does not support authorization_code")
		return
	}
	if len(client.RedirectURIs) > 0 {
		if redirectURI == "" {
			redirectURI = client.RedirectURIs[0]
		}
		if !contains(client.RedirectURIs, redirectURI) {
			writeAPIError(w, http.StatusBadRequest, "invalid redirect_uri")
			return
		}
	}
	if client.RequirePKCE && codeChallenge == "" {
		writeAPIError(w, http.StatusBadRequest, "pkce is required")
		return
	}
	userSession, ok := s.currentOAuthUser(r)
	if !ok {
		next := r.URL.RequestURI()
		http.Redirect(w, r, canonicalOpenIDBasePath+"/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	requestedScopes := splitScopes(scopeParam)
	if len(requestedScopes) == 0 {
		requestedScopes = client.Scopes
	}
	consentScopes, err := s.store.FindOAuthConsent(client.ClientID, userSession.Username)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !containsAll(consentScopes, requestedScopes) {
		params := url.Values{}
		params.Set("client_id", client.ClientID)
		params.Set("state", state)
		params.Set("scope", strings.Join(requestedScopes, " "))
		params.Set("redirect_uri", redirectURI)
		if codeChallenge != "" {
			params.Set("code_challenge", codeChallenge)
			params.Set("code_challenge_method", challengeMethod)
		}
		http.Redirect(w, r, canonicalOpenIDBasePath+"/consent?"+params.Encode(), http.StatusFound)
		return
	}
	code, err := randomToken(32)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	attributesRaw, _ := json.Marshal(map[string]any{
		"redirect_uri":          redirectURI,
		"code_challenge":        codeChallenge,
		"code_challenge_method": challengeMethod,
	})
	authID := uuid.NewString()
	now := time.Now().UTC()
	err = s.store.SaveOAuthCode(store.OAuthAuthorization{
		ID:                         authID,
		RegisteredClientID:         client.ID,
		PrincipalName:              userSession.Username,
		AuthorizationGrantType:     "authorization_code",
		AuthorizedScopes:           strings.Join(requestedScopes, ","),
		Attributes:                 attributesRaw,
		State:                      sql.NullString{String: state, Valid: state != ""},
		AuthorizationCodeValue:     []byte(code),
		AuthorizationCodeIssuedAt:  sql.NullTime{Time: now, Valid: true},
		AuthorizationCodeExpiresAt: sql.NullTime{Time: now.Add(5 * time.Minute), Valid: true},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid redirect_uri")
		return
	}
	q := redirect.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid form payload")
		return
	}
	client, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	grantType := strings.TrimSpace(r.FormValue("grant_type"))
	switch grantType {
	case "authorization_code":
		s.handleOAuthTokenByAuthCode(w, r, client)
	case "refresh_token":
		s.handleOAuthTokenByRefresh(w, r, client)
	default:
		writeAPIError(w, http.StatusBadRequest, "unsupported grant_type")
	}
}

func (s *Server) handleOAuthTokenByAuthCode(w http.ResponseWriter, r *http.Request, client *store.OAuthClient) {
	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))
	if code == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	auth, err := s.store.FindOAuthByCode(code)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if auth.RegisteredClientID != client.ID {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !auth.AuthorizationCodeExpiresAt.Valid || auth.AuthorizationCodeExpiresAt.Time.Before(time.Now().UTC()) {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if len(auth.AccessTokenValue) > 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	attrs := map[string]any{}
	if len(auth.Attributes) > 0 {
		_ = json.Unmarshal(auth.Attributes, &attrs)
	}
	storedRedirect, _ := attrs["redirect_uri"].(string)
	if storedRedirect != "" && redirectURI != "" && storedRedirect != redirectURI {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if client.RequirePKCE {
		if !verifyPKCE(attrs, codeVerifier) {
			writeAPIError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}
	user, err := s.store.FindUserByUsername(auth.PrincipalName)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	scopes := splitCSV(auth.AuthorizedScopes)
	accessToken, accessIssuedAt, accessExpAt, err := s.issueOAuthAccessToken(user, client.ClientID, scopes)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	refreshToken, err := randomToken(32)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	refreshIssuedAt := time.Now().UTC()
	refreshExpAt := refreshIssuedAt.Add(s.cfg.TokenRefreshTTL)
	if err := s.store.SaveOAuthTokens(auth.ID, accessToken, refreshToken, accessIssuedAt, accessExpAt, refreshIssuedAt, refreshExpAt, scopes); err != nil {
		writeInternalError(w, err)
		return
	}
	username := user.Username
	_ = s.store.RecordTokenAudit("OAUTH_ACCESS", accessToken, &username, nil, nil, &client.ClientID, &auth.ID, accessIssuedAt, &accessExpAt)
	_ = s.store.RecordTokenAudit("OAUTH_REFRESH", refreshToken, &username, nil, nil, &client.ClientID, &auth.ID, refreshIssuedAt, &refreshExpAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.TokenAccessTTL.Seconds()),
		"refresh_token": refreshToken,
		"scope":         strings.Join(scopes, " "),
	})
}

func (s *Server) handleOAuthTokenByRefresh(w http.ResponseWriter, r *http.Request, client *store.OAuthClient) {
	refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
	if refreshToken == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	auth, err := s.store.FindOAuthByRefreshToken(refreshToken)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if auth.RegisteredClientID != client.ID {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !auth.RefreshTokenExpiresAt.Valid || auth.RefreshTokenExpiresAt.Time.Before(time.Now().UTC()) {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	user, err := s.store.FindUserByUsername(auth.PrincipalName)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	scopes := splitCSV(auth.AuthorizedScopes)
	accessToken, accessIssuedAt, accessExpAt, err := s.issueOAuthAccessToken(user, client.ClientID, scopes)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	nextRefreshToken := refreshToken
	refreshIssuedAt := auth.RefreshTokenIssuedAt.Time
	refreshExpAt := auth.RefreshTokenExpiresAt.Time
	if s.cfg.TokenRotateRefresh {
		nextRefreshToken, err = randomToken(32)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		refreshIssuedAt = time.Now().UTC()
		refreshExpAt = refreshIssuedAt.Add(s.cfg.TokenRefreshTTL)
	}
	if err := s.store.ReplaceOAuthTokens(auth.ID, accessToken, nextRefreshToken, accessIssuedAt, accessExpAt, refreshIssuedAt, refreshExpAt, scopes, s.cfg.TokenRotateRefresh); err != nil {
		writeInternalError(w, err)
		return
	}
	username := user.Username
	_ = s.store.RecordTokenAudit("OAUTH_ACCESS", accessToken, &username, nil, nil, &client.ClientID, &auth.ID, accessIssuedAt, &accessExpAt)
	if s.cfg.TokenRotateRefresh {
		_ = s.store.RecordTokenAudit("OAUTH_REFRESH", nextRefreshToken, &username, nil, nil, &client.ClientID, &auth.ID, refreshIssuedAt, &refreshExpAt)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.TokenAccessTTL.Seconds()),
		"refresh_token": nextRefreshToken,
		"scope":         strings.Join(scopes, " "),
	})
}

func (s *Server) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if token != "" {
		_ = s.store.RevokeOAuthByToken(token)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOAuthIntrospect(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	auth, err := s.store.FindOAuthByAccessToken(token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if auth.AccessTokenExpiresAt.Valid && auth.AccessTokenExpiresAt.Time.Before(time.Now().UTC()) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	registeredClient, err := s.store.FindClientByInternalID(auth.RegisteredClientID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":            true,
		"scope":             strings.Join(splitCSV(auth.AuthorizedScopes), " "),
		"client_id":         registeredClient.ClientID,
		"username":          auth.PrincipalName,
		"token_type":        "Bearer",
		"exp":               auth.AccessTokenExpiresAt.Time.Unix(),
		"iat":               auth.AccessTokenIssuedAt.Time.Unix(),
		"sub":               auth.PrincipalName,
		"iss":               s.cfg.Issuer,
		"aud":               []string{"app-api"},
		"requesting_client": client.ClientID,
	})
}

func (s *Server) authenticateOAuthClient(w http.ResponseWriter, r *http.Request) (*store.OAuthClient, bool) {
	clientID := ""
	clientSecret := ""
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "basic ") {
		parts := strings.SplitN(authz, " ", 2)
		encoded := ""
		if len(parts) == 2 {
			encoded = strings.TrimSpace(parts[1])
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			clientID = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				clientSecret = parts[1]
			}
		}
	}
	if err := r.ParseForm(); err == nil {
		if clientID == "" {
			clientID = strings.TrimSpace(r.FormValue("client_id"))
		}
		if clientSecret == "" {
			clientSecret = r.FormValue("client_secret")
		}
	}
	if clientID == "" {
		writeAPIError(w, http.StatusUnauthorized, "invalid client")
		return nil, false
	}
	client, err := s.store.FindActiveClient(clientID)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid client")
		return nil, false
	}
	allowsNone := contains(client.AuthMethods, "none") || len(client.AuthMethods) == 0
	if client.ClientSecret == "" {
		if !allowsNone {
			writeAPIError(w, http.StatusUnauthorized, "invalid client")
			return nil, false
		}
		return client, true
	}
	if strings.TrimSpace(clientSecret) == "" || bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)) != nil {
		writeAPIError(w, http.StatusUnauthorized, "invalid client")
		return nil, false
	}
	return client, true
}

func (s *Server) issueAppAccessToken(username, deviceID string, ttl time.Duration) (token string, issuedAt, expiresAt time.Time, err error) {
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)
	claims := map[string]any{
		"iss":       s.cfg.Issuer,
		"sub":       username,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"scope":     "app",
		"device_id": deviceID,
	}
	tkn, err := security.SignJWT(key, claims)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	return tkn, now, exp, nil
}

func (s *Server) issueAccountAppAccessToken(user *store.User, device store.AccountSession, ttl time.Duration) (token string, issuedAt, expiresAt time.Time, err error) {
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(ttl)
	claims := map[string]any{
		"iss":        s.cfg.Issuer,
		"sub":        user.Username,
		"account_id": user.UserID,
		"device_id":  device.DeviceID,
		"iat":        now.Unix(),
		"exp":        expiresAt.Unix(),
		"scope":      "app tunnel",
		"aud":        []string{"app", "tunnel"},
	}
	token, err = security.SignJWT(key, claims)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	return token, now, expiresAt, nil
}

func (s *Server) authenticateAppAccessToken(token string) (*model.AppPrincipal, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("empty token")
	}
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := security.ParseAndVerifyJWT(token, key, &claims); err != nil {
		return nil, err
	}
	if toString(claims["iss"]) != s.cfg.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if !stringsContainWord(toString(claims["scope"]), "app") {
		return nil, fmt.Errorf("invalid scope")
	}
	expUnix := toInt64(claims["exp"])
	if expUnix <= time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}
	deviceID := toString(claims["device_id"])
	if _, err := uuid.Parse(deviceID); err != nil {
		return nil, fmt.Errorf("invalid device id")
	}
	issuedAtUnix := toInt64(claims["iat"])
	accountID := toString(claims["account_id"])
	if accountID != "" {
		device, err := s.store.FindAccountSessionByID(accountID, deviceID)
		if err != nil || device.Status != "ACTIVE" {
			return nil, fmt.Errorf("device revoked")
		}
		user, err := s.store.FindUserByID(accountID)
		if err != nil || user.Status != "ACTIVE" || user.Username != toString(claims["sub"]) {
			return nil, fmt.Errorf("account inactive")
		}
		if err := s.store.TouchAccountSession(accountID, deviceID); err != nil {
			return nil, err
		}
		return &model.AppPrincipal{
			Username: toString(claims["sub"]), AccountID: accountID, DeviceID: deviceID,
			IssuedAt: time.Unix(issuedAtUnix, 0).UTC(),
		}, nil
	}
	active, err := s.store.IsDeviceActive(deviceID)
	if err != nil || !active {
		return nil, fmt.Errorf("device revoked")
	}
	_ = s.store.TouchDevice(deviceID)
	return &model.AppPrincipal{Username: toString(claims["sub"]), DeviceID: deviceID, IssuedAt: time.Unix(issuedAtUnix, 0).UTC()}, nil
}

func stringsContainWord(value, expected string) bool {
	for _, word := range strings.Fields(value) {
		if word == expected {
			return true
		}
	}
	return false
}

func (s *Server) issueOAuthAccessToken(user *store.User, clientID string, scopes []string) (token string, issuedAt, expiresAt time.Time, err error) {
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	exp := now.Add(s.cfg.TokenAccessTTL)
	scopeText := strings.Join(scopes, " ")
	claims := map[string]any{
		"iss":                s.cfg.Issuer,
		"sub":                user.UserID,
		"iat":                now.Unix(),
		"exp":                exp.Unix(),
		"scope":              scopeText,
		"preferred_username": user.Username,
		"display_name":       user.DisplayName,
		"aud":                []string{"app-api"},
		"client_id":          clientID,
	}
	tkn, err := security.SignJWT(key, claims)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	return tkn, now, exp, nil
}

func (s *Server) verifyOAuthAccessToken(token string) (map[string]any, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("empty token")
	}
	key, err := s.keys.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := security.ParseAndVerifyJWT(token, key, &claims); err != nil {
		return nil, err
	}
	if toString(claims["iss"]) != s.cfg.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	exp := toInt64(claims["exp"])
	if exp <= time.Now().Unix() {
		return nil, fmt.Errorf("expired")
	}
	validAudience := claims["aud"] == "app-api"
	if audiences, ok := claims["aud"].([]any); ok {
		for _, audience := range audiences {
			if audience == "app-api" {
				validAudience = true
				break
			}
		}
	}
	clientID, _ := claims["client_id"].(string)
	if !validAudience || strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("not oauth token")
	}
	return claims, nil
}

func (s *Server) resolveAccessTTL(requested *int) (time.Duration, error) {
	if requested == nil {
		return s.cfg.AppAccessTTL, nil
	}
	if *requested <= 0 {
		return 0, fmt.Errorf("accessTtlSeconds must be positive")
	}
	value := time.Duration(*requested) * time.Second
	if value > s.cfg.AppMaxAccessTTL {
		return 0, fmt.Errorf("requested access ttl exceeds limit, max seconds=%d", int(s.cfg.AppMaxAccessTTL.Seconds()))
	}
	return value, nil
}

func verifyPKCE(attrs map[string]any, codeVerifier string) bool {
	storedChallenge, _ := attrs["code_challenge"].(string)
	method, _ := attrs["code_challenge_method"].(string)
	if storedChallenge == "" {
		return false
	}
	if method == "" || strings.EqualFold(method, "plain") {
		return codeVerifier == storedChallenge
	}
	if strings.EqualFold(method, "S256") {
		sum := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		return computed == storedChallenge
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func writeInternalError(w http.ResponseWriter, err error) {
	writeAPIError(w, http.StatusInternalServerError, "internal server error")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func writeSQLError(w http.ResponseWriter, err error) {
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		writeAPIError(w, http.StatusConflict, "resource already exists")
		return
	}
	writeInternalError(w, err)
}

func normalizeStatus(status string) string {
	value := strings.ToUpper(strings.TrimSpace(status))
	if value == "ACTIVE" || value == "DISABLED" {
		return value
	}
	return ""
}

func normalizeStatusOrDefault(status string) string {
	value := normalizeStatus(status)
	if value == "" {
		return "ACTIVE"
	}
	return value
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func containsAll(have, want []string) bool {
	index := map[string]struct{}{}
	for _, item := range have {
		index[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
	}
	for _, item := range want {
		if _, ok := index[strings.ToLower(strings.TrimSpace(item))]; !ok {
			return false
		}
	}
	return true
}

func splitScopes(value string) []string {
	parts := strings.Fields(strings.TrimSpace(value))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitCSV(values string) []string {
	parts := strings.Split(values, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitCSVQuery(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			out = append(out, strings.ToUpper(item))
		}
	}
	return out
}

func parseIntDefault(raw string, fallback int) int {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func bearerToken(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return ""
	}
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}

func randomToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
