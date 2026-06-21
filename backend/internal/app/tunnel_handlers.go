package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"identity-center/backend/internal/model"
	"identity-center/backend/internal/store"
)

var tunnelDeviceIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var reservedTunnelDeviceIDs = map[string]struct{}{
	"admin":  {},
	"api":    {},
	"relay":  {},
	"tunnel": {},
	"www":    {},
}

func (s *Server) handleDesktopDeviceRegister(w http.ResponseWriter, r *http.Request) {
	principal, err := s.authenticateAppAccessToken(bearerToken(r))
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		DeviceID    string `json:"deviceId"`
		DeviceName  string `json:"deviceName"`
		RotateToken bool   `json:"rotateToken"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	deviceID := normalizeTunnelDeviceID(req.DeviceID)
	if !isValidTunnelDeviceID(deviceID) {
		writeAPIError(w, http.StatusBadRequest, "invalid deviceId")
		return
	}
	if existing, err := s.store.FindTunnelDesktopByID(deviceID); err == nil && !existing.Enabled {
		writeAPIError(w, http.StatusForbidden, "desktop is disabled")
		return
	} else if err != nil && err != sql.ErrNoRows {
		writeInternalError(w, err)
		return
	}

	agentToken, err := randomToken(32)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(agentToken), bcrypt.DefaultCost)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	publicHost := s.tunnelDesktopPublicHost(deviceID)
	desktop, err := s.store.UpsertTunnelDesktopRegistration(store.TunnelDesktopRegistration{
		DeviceID:         deviceID,
		DeviceName:       req.DeviceName,
		Username:         principal.Username,
		AgentTokenBcrypt: string(tokenHash),
		PublicHost:       publicHost,
		PublicURL:        "https://" + publicHost,
		WebSocketURL:     "wss://" + publicHost + "/ws",
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_ = s.store.RecordTunnelActivity(store.TunnelActivityCreate{
		ObjectType: "desktop",
		ObjectID:   deviceID,
		EventType:  "desktop.registered",
		Actor:      principal.Username,
		Message:    fmt.Sprintf("Desktop %s registered", deviceID),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":     desktop.DeviceID,
		"publicHost":   desktop.PublicHost,
		"publicUrl":    desktop.PublicURL,
		"webSocketUrl": desktop.WebSocketURL,
		"relayUrl":     s.tunnelHubRelayURL(),
		"agentToken":   agentToken,
	})
}

func (s *Server) handleAdminTunnelOverview(w http.ResponseWriter, r *http.Request) {
	bucket := normalizeTunnelBucket(r.URL.Query().Get("bucket"))
	desktops, err := s.store.ListTunnelDesktops("", "ALL")
	if err != nil {
		writeInternalError(w, err)
		return
	}
	webapps, err := s.store.ListTunnelWebapps("", "ALL")
	if err != nil {
		writeInternalError(w, err)
		return
	}
	activities, err := s.store.ListTunnelActivities("", "", 1)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	rawTraffic, err := s.store.AggregateTunnelTraffic(bucket, tunnelTrafficSince(bucket), 720)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	var (
		activeDesktopConnections int
		activeWebappConnections  int64
		enabledDesktops          int
		disabledDesktops         int
		enabledWebapps           int
		disabledWebapps          int
		totalBytesIn             int64
		totalBytesOut            int64
		lastConnectionAt         *time.Time
		lastConnectionActor      string
		lastConnectionObjectID   string
		lastConnectionObjectType string
	)
	for _, desktop := range desktops {
		if desktop.Enabled {
			enabledDesktops += 1
		} else {
			disabledDesktops += 1
		}
		if desktop.Status == store.TunnelDesktopStatusConnected {
			activeDesktopConnections += 1
		}
		totalBytesIn += desktop.BytesIn
		totalBytesOut += desktop.BytesOut
		if updateLastConnection(&lastConnectionAt, desktop.LastSeenAt) || updateLastConnection(&lastConnectionAt, desktop.ConnectedAt) {
			lastConnectionActor = desktop.Username
			lastConnectionObjectID = desktop.DeviceID
			lastConnectionObjectType = "desktop"
		}
	}
	for _, webapp := range webapps {
		if webapp.Enabled {
			enabledWebapps += 1
		} else {
			disabledWebapps += 1
		}
		activeWebappConnections += webapp.Connections
		totalBytesIn += webapp.BytesIn
		totalBytesOut += webapp.BytesOut
		if updateLastConnection(&lastConnectionAt, webapp.LastAccessedAt) {
			lastConnectionActor = ""
			lastConnectionObjectID = webapp.RouteID
			lastConnectionObjectType = "webapp"
		}
	}
	if lastConnectionAt == nil && len(activities) > 0 {
		t := activities[0].CreateAt
		lastConnectionAt = &t
		lastConnectionActor = activities[0].Actor
		lastConnectionObjectID = activities[0].ObjectID
		lastConnectionObjectType = activities[0].ObjectType
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"bucket": bucket,
		"metrics": map[string]any{
			"activeDesktopConnections": activeDesktopConnections,
			"activeWebappConnections":  activeWebappConnections,
			"totalBytesIn":             totalBytesIn,
			"totalBytesOut":            totalBytesOut,
			"totalTrafficBytes":        totalBytesIn + totalBytesOut,
			"lastConnectionAt":         lastConnectionAt,
			"lastConnectionActor":      lastConnectionActor,
			"lastConnectionObjectId":   lastConnectionObjectID,
			"lastConnectionObjectType": lastConnectionObjectType,
		},
		"resources": map[string]any{
			"totalDesktops":    len(desktops),
			"enabledDesktops":  enabledDesktops,
			"disabledDesktops": disabledDesktops,
			"totalWebapps":     len(webapps),
			"enabledWebapps":   enabledWebapps,
			"disabledWebapps":  disabledWebapps,
		},
		"traffic": buildTunnelTrafficSeries(bucket, rawTraffic),
	})
}

func (s *Server) handleAdminTunnelDesktops(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListTunnelDesktops(r.URL.Query().Get("q"), r.URL.Query().Get("status"))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleAdminTunnelDesktopClose(w http.ResponseWriter, r *http.Request) {
	deviceID := normalizeTunnelDeviceID(chi.URLParam(r, "deviceId"))
	desktop, err := s.store.CloseTunnelDesktop(deviceID)
	if err == sql.ErrNoRows {
		writeAPIError(w, http.StatusNotFound, "desktop not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_ = s.store.RecordTunnelActivity(store.TunnelActivityCreate{
		ObjectType: "desktop",
		ObjectID:   deviceID,
		EventType:  "desktop.closed",
		Actor:      adminActor(r),
		Message:    fmt.Sprintf("Desktop %s connection closed", deviceID),
	})
	writeJSON(w, http.StatusOK, desktop)
}

func (s *Server) handleAdminTunnelDesktopPatch(w http.ResponseWriter, r *http.Request) {
	deviceID := normalizeTunnelDeviceID(chi.URLParam(r, "deviceId"))
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeAPIError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	desktop, err := s.store.SetTunnelDesktopEnabled(deviceID, *req.Enabled)
	if err == sql.ErrNoRows {
		writeAPIError(w, http.StatusNotFound, "desktop not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	eventType := "desktop.enabled"
	if !*req.Enabled {
		eventType = "desktop.disabled"
	}
	_ = s.store.RecordTunnelActivity(store.TunnelActivityCreate{
		ObjectType: "desktop",
		ObjectID:   deviceID,
		EventType:  eventType,
		Actor:      adminActor(r),
		Message:    fmt.Sprintf("Desktop %s enabled=%t", deviceID, *req.Enabled),
	})
	writeJSON(w, http.StatusOK, desktop)
}

func (s *Server) handleAdminTunnelWebapps(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListTunnelWebapps(r.URL.Query().Get("q"), r.URL.Query().Get("status"))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleAdminTunnelActivity(w http.ResponseWriter, r *http.Request) {
	limit := parseIntDefault(r.URL.Query().Get("limit"), 100)
	rows, err := s.store.ListTunnelActivities(r.URL.Query().Get("q"), r.URL.Query().Get("type"), limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func normalizeTunnelDeviceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidTunnelDeviceID(value string) bool {
	if _, ok := reservedTunnelDeviceIDs[value]; ok {
		return false
	}
	return tunnelDeviceIDPattern.MatchString(value)
}

func (s *Server) tunnelDesktopPublicHost(deviceID string) string {
	return normalizeTunnelDeviceID(deviceID) + ".m." + s.tunnelHubBaseDomain()
}

func (s *Server) tunnelHubBaseDomain() string {
	domain := strings.Trim(strings.TrimSpace(s.cfg.TunnelHubBaseDomain), ".")
	domain = strings.TrimPrefix(domain, "*.")
	if domain == "" {
		return "zenmind.cc"
	}
	return domain
}

func (s *Server) tunnelHubRelayURL() string {
	if configured := strings.TrimSpace(s.cfg.TunnelHubRelayURL); configured != "" {
		return configured
	}
	issuer := strings.TrimSpace(s.cfg.Issuer)
	if issuer != "" {
		if parsed, err := url.Parse(issuer); err == nil && parsed.Host != "" {
			switch parsed.Scheme {
			case "http":
				parsed.Scheme = "ws"
			case "https":
				parsed.Scheme = "wss"
			default:
				parsed.Scheme = "wss"
			}
			parsed.Path = "/tunnel"
			parsed.RawQuery = ""
			parsed.Fragment = ""
			return parsed.String()
		}
	}
	return "wss://tunnel-hub." + s.tunnelHubBaseDomain() + "/tunnel"
}

func normalizeTunnelBucket(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "day":
		return "day"
	case "month":
		return "month"
	default:
		return "hour"
	}
}

func tunnelTrafficSince(bucket string) time.Time {
	now := time.Now().UTC()
	switch bucket {
	case "day":
		return now.AddDate(0, 0, -30)
	case "month":
		return now.AddDate(-1, 0, 0)
	default:
		return now.Add(-24 * time.Hour)
	}
}

func buildTunnelTrafficSeries(bucket string, raw []store.TunnelTrafficPoint) []map[string]any {
	count := 24
	start := time.Now().UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	step := func(t time.Time, n int) time.Time { return t.Add(time.Duration(n) * time.Hour) }
	key := func(t time.Time) string { return t.Format("2006-01-02T15:00:00Z") }
	if bucket == "day" {
		count = 30
		now := time.Now().UTC()
		start = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -29)
		step = func(t time.Time, n int) time.Time { return t.AddDate(0, 0, n) }
		key = func(t time.Time) string { return t.Format("2006-01-02T00:00:00Z") }
	} else if bucket == "month" {
		count = 12
		now := time.Now().UTC()
		start = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -11, 0)
		step = func(t time.Time, n int) time.Time { return t.AddDate(0, n, 0) }
		key = func(t time.Time) string { return t.Format("2006-01-01T00:00:00Z") }
	}
	byBucket := make(map[string]store.TunnelTrafficPoint, len(raw))
	for _, point := range raw {
		byBucket[key(point.BucketStart)] = point
	}
	out := make([]map[string]any, 0, count)
	for i := 0; i < count; i += 1 {
		t := step(start, i)
		point := byBucket[key(t)]
		totalIn := point.DesktopBytesIn + point.WebappBytesIn
		totalOut := point.DesktopBytesOut + point.WebappBytesOut
		out = append(out, map[string]any{
			"bucketStart":     t,
			"desktopBytesIn":  point.DesktopBytesIn,
			"desktopBytesOut": point.DesktopBytesOut,
			"webappBytesIn":   point.WebappBytesIn,
			"webappBytesOut":  point.WebappBytesOut,
			"totalBytesIn":    totalIn,
			"totalBytesOut":   totalOut,
			"totalBytes":      totalIn + totalOut,
		})
	}
	return out
}

func updateLastConnection(current **time.Time, candidate *time.Time) bool {
	if candidate == nil {
		return false
	}
	if *current == nil || candidate.After(**current) {
		t := candidate.UTC()
		*current = &t
		return true
	}
	return false
}

func adminActor(r *http.Request) string {
	if session, ok := r.Context().Value(ctxAdminSessionKey).(model.AdminSession); ok {
		return session.Username
	}
	return "admin"
}
