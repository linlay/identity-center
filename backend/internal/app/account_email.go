package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"identity-center/backend/internal/store"
)

func (s *Server) emailReady(w http.ResponseWriter, purpose string) bool {
	if !s.cfg.Email.Ready() || (purpose == "login" && !s.cfg.Email.LoginEnabled) || (purpose == "bind" && !s.cfg.Email.BindEnabled) {
		writeEmailError(w, store.ErrEmailSend)
		return false
	}
	return true
}
func (s *Server) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.currentAccountPrincipal(w, r)
	if !ok {
		return
	}
	user, err := s.store.FindUserByID(principal.AccountID)
	if err != nil || user.Status != "ACTIVE" {
		writeAPIError(w, 401, "account session required")
		return
	}
	binding, err := s.store.AccountEmail(principal.AccountID)
	if err != nil {
		writeEmailError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"schemaVersion": 1, "accountId": user.UserID, "username": user.Username, "emailBinding": binding})
}
func emailRequestIP(r *http.Request) string {
	peer, _ := r.Context().Value(emailPeerKey).(string)
	if peer == "" {
		peer = r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(peer)
	if err == nil {
		return host
	}
	return peer
}
func (s *Server) handleEmailLoginChallenge(w http.ResponseWriter, r *http.Request) {
	s.handleEmailChallenge(w, r, "login")
}
func (s *Server) handleEmailBindChallenge(w http.ResponseWriter, r *http.Request) {
	s.handleEmailChallenge(w, r, "bind")
}
func (s *Server) handleEmailUnbindChallenge(w http.ResponseWriter, r *http.Request) {
	s.handleEmailChallenge(w, r, "unbind")
}
func (s *Server) handleEmailChallenge(w http.ResponseWriter, r *http.Request, purpose string) {
	if !s.emailReady(w, purpose) {
		return
	}
	var req struct {
		Email     string `json:"email"`
		RequestID string `json:"requestId"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !decodeJSON(w, r, &req) {
		return
	}
	account, device := "", ""
	if purpose != "login" {
		p, ok := s.currentAccountPrincipal(w, r)
		if !ok {
			return
		}
		account, device = p.AccountID, p.DeviceID
	}
	cfg := s.cfg.Email
	now := time.Now().UTC()
	if uuid.Validate(req.RequestID) != nil {
		writeEmailError(w, store.ErrEmailFormat)
		return
	}
	if purpose != "unbind" {
		if _, _, err := store.NormalizeEmail(req.Email); err != nil {
			writeEmailError(w, err)
			return
		}
	}
	c, code, fresh, err := s.store.ReserveEmailChallenge(store.EmailChallengeInput{
		ResponseDelay: cfg.Timeout, Purpose: purpose, Email: req.Email, AccountID: account, DeviceID: device, IP: emailRequestIP(r), RequestID: req.RequestID, Secret: cfg.DigestKey,
		Limits: store.EmailLimits{EmailHour: cfg.EmailHour, EmailDay: cfg.EmailDay, AccountHour: cfg.AccountHour, AccountDay: cfg.AccountDay, IPHour: cfg.IPHour, IPDay: cfg.IPDay, FailureHour: cfg.FailureHour},
	}, now)
	if err != nil {
		writeEmailError(w, err)
		return
	}
	if fresh {
		accepted := c.Email == "" // Unknown login mailboxes never send a message.
		if c.Email != "" {
			ctx, cancel := context.WithDeadline(r.Context(), now.Add(cfg.Timeout))
			err = s.sendEmail(ctx, c.Email, purpose, code)
			cancel()
			accepted = err == nil
			if err != nil {
				s.logger.Print("account email SMTP send unconfirmed")
			}
		}
		completedAt := time.Now().UTC()
		if purpose == "login" {
			completedAt = now.Add(cfg.Timeout)
		}
		if err := s.store.FinishEmailSend(c, accepted, cfg.DigestKey, completedAt); err != nil {
			if purpose != "login" || !errors.Is(err, store.ErrEmailChallenge) {
				writeEmailError(w, err)
				return
			}
			// A concurrent unbind must not reveal that this public mailbox was bound.
			s.logger.Print("account email challenge invalidated during delivery")
		}
		if !accepted && purpose != "login" {
			writeEmailError(w, store.ErrEmailSend)
			return
		}
	}
	// Public timing fields are derived from reservation time for every mailbox, never SMTP duration.
	if purpose == "login" {
		deadline := now.Add(cfg.Timeout)
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
		c.ServerTime = deadline
	}
	writeJSON(w, 200, c)
}
func (s *Server) handleEmailLogin(w http.ResponseWriter, r *http.Request) {
	s.handleEmailConsume(w, r, "login")
}
func (s *Server) handleEmailBind(w http.ResponseWriter, r *http.Request) {
	s.handleEmailConsume(w, r, "bind")
}
func (s *Server) handleEmailUnbind(w http.ResponseWriter, r *http.Request) {
	s.handleEmailConsume(w, r, "unbind")
}
func (s *Server) handleEmailConsume(w http.ResponseWriter, r *http.Request, purpose string) {
	if !s.emailReady(w, purpose) {
		return
	}
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
		DeviceName  string `json:"deviceName"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !decodeJSON(w, r, &req) {
		return
	}
	if purpose == "login" && (strings.TrimSpace(req.DeviceName) == "" || len([]rune(strings.TrimSpace(req.DeviceName))) > 64) {
		writeEmailError(w, store.ErrEmailFormat)
		return
	}
	account, device := "", ""
	if purpose != "login" {
		p, ok := s.currentAccountPrincipal(w, r)
		if !ok {
			return
		}
		account, device = p.AccountID, p.DeviceID
	}
	result, err := s.store.ConsumeEmailChallenge(store.EmailConsumeInput{ID: req.ChallengeID, Code: req.Code, Purpose: purpose, AccountID: account, DeviceID: device, IP: emailRequestIP(r), Secret: s.cfg.Email.DigestKey, DeviceName: req.DeviceName, FailureHour: s.cfg.Email.FailureHour}, time.Now().UTC())
	if err != nil {
		writeEmailError(w, err)
		return
	}
	if purpose == "login" {
		ttl, err := s.resolveAccessTTL(nil)
		if err != nil {
			writeEmailError(w, err)
			return
		}
		session, err := s.finishAccountAppLoginSession(result.User, *result.Session, ttl)
		if err != nil {
			writeEmailError(w, err)
			return
		}
		writeJSON(w, 200, session)
		return
	}
	writeJSON(w, 200, map[string]any{"schemaVersion": 1, "accountId": result.User.UserID, "username": result.User.Username, "emailBinding": result.Binding})
}
func (s *Server) handleAdminUnbindEmail(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.currentAdminSession(r)
	if !ok {
		writeAPIError(w, 401, "admin session required")
		return
	}
	var req struct {
		Reason    string `json:"reason"`
		Confirmed bool   `json:"confirmed"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirmed {
		writeEmailError(w, store.ErrEmailFormat)
		return
	}
	if err := s.store.AdminUnbindAccountEmail(chi.URLParam(r, "userId"), admin.Username, req.Reason, s.cfg.Email.DigestKey, time.Now().UTC()); err != nil {
		writeEmailError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func writeEmailError(w http.ResponseWriter, err error) {
	status, code := 503, "email_unavailable_service"
	var rate *store.EmailRateError
	switch {
	case errors.As(err, &rate):
		status, code = 429, "email_rate_limited"
		w.Header().Set("Retry-After", strconv.FormatInt(max(1, (rate.RetryAt-time.Now().UnixMilli()+999)/1000), 10))
	case errors.Is(err, store.ErrEmailFormat):
		status, code = 400, "email_invalid_request"
	case errors.Is(err, store.ErrEmailUnavailable):
		status, code = 409, "email_unavailable"
	case errors.Is(err, store.ErrEmailChallenge):
		status, code = 401, "email_authentication_failed"
	}
	payload := map[string]any{"error": code, "serverTime": time.Now().UTC()}
	if rate != nil {
		payload["retryAt"] = time.UnixMilli(rate.RetryAt).UTC()
	}
	writeJSON(w, status, payload)
}

const emailPeerKey contextKey = "email_peer"

// Keep quota keys tied to the TCP peer; arbitrary forwarded headers cannot bypass limits.
func (s *Server) rememberEmailPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), emailPeerKey, r.RemoteAddr)))
	})
}
