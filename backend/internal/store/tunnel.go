package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TunnelDesktopStatusOffline   = "OFFLINE"
	TunnelDesktopStatusDisabled  = "DISABLED"
	TunnelDesktopStatusConnected = "CONNECTED"
)

type TunnelDesktop struct {
	DeviceID           string     `json:"deviceId"`
	DeviceName         string     `json:"deviceName"`
	Username           string     `json:"username"`
	Status             string     `json:"status"`
	Enabled            bool       `json:"enabled"`
	PublicHost         string     `json:"publicHost"`
	PublicURL          string     `json:"publicUrl"`
	WebSocketURL       string     `json:"webSocketUrl"`
	CurrentSessionID   string     `json:"currentSessionId,omitempty"`
	ConnectedAt        *time.Time `json:"connectedAt,omitempty"`
	LastSeenAt         *time.Time `json:"lastSeenAt,omitempty"`
	LastDisconnectedAt *time.Time `json:"lastDisconnectedAt,omitempty"`
	BytesIn            int64      `json:"bytesIn"`
	BytesOut           int64      `json:"bytesOut"`
	CreateAt           time.Time  `json:"createAt"`
	UpdateAt           time.Time  `json:"updateAt"`
}

type TunnelWebapp struct {
	RouteID        string     `json:"routeId"`
	Name           string     `json:"name"`
	PublicHost     string     `json:"publicHost"`
	PublicURL      string     `json:"publicUrl"`
	UpstreamURL    string     `json:"upstreamUrl"`
	Status         string     `json:"status"`
	Enabled        bool       `json:"enabled"`
	Connections    int64      `json:"connections"`
	LastAccessedAt *time.Time `json:"lastAccessedAt,omitempty"`
	BytesIn        int64      `json:"bytesIn"`
	BytesOut       int64      `json:"bytesOut"`
	CreateAt       time.Time  `json:"createAt"`
	UpdateAt       time.Time  `json:"updateAt"`
}

type TunnelActivity struct {
	ActivityID string    `json:"activityId"`
	ObjectType string    `json:"objectType"`
	ObjectID   string    `json:"objectId"`
	EventType  string    `json:"eventType"`
	Actor      string    `json:"actor"`
	Message    string    `json:"message"`
	BytesIn    int64     `json:"bytesIn"`
	BytesOut   int64     `json:"bytesOut"`
	CreateAt   time.Time `json:"createAt"`
}

type TunnelActivityCreate struct {
	ObjectType string
	ObjectID   string
	EventType  string
	Actor      string
	Message    string
	BytesIn    int64
	BytesOut   int64
}

type TunnelTrafficPoint struct {
	BucketStart     time.Time `json:"bucketStart"`
	DesktopBytesIn  int64     `json:"desktopBytesIn"`
	DesktopBytesOut int64     `json:"desktopBytesOut"`
	WebappBytesIn   int64     `json:"webappBytesIn"`
	WebappBytesOut  int64     `json:"webappBytesOut"`
}

type TunnelDesktopRegistration struct {
	DeviceID         string
	DeviceName       string
	Username         string
	AgentTokenBcrypt string
	PublicHost       string
	PublicURL        string
	WebSocketURL     string
}

func (s *Store) FindTunnelDesktopByID(deviceID string) (*TunnelDesktop, error) {
	row := s.db.QueryRow(`SELECT DEVICE_ID_, DEVICE_NAME_, USERNAME_, STATUS_, ENABLED_, PUBLIC_HOST_, PUBLIC_URL_, WEB_SOCKET_URL_, CURRENT_SESSION_ID_, CONNECTED_AT_, LAST_SEEN_AT_, LAST_DISCONNECTED_AT_, BYTES_IN_, BYTES_OUT_, CREATE_AT_, UPDATE_AT_ FROM TUNNEL_DESKTOP_ WHERE DEVICE_ID_ = ?`, strings.TrimSpace(deviceID))
	return scanTunnelDesktop(row)
}

func (s *Store) UpsertTunnelDesktopRegistration(req TunnelDesktopRegistration) (*TunnelDesktop, error) {
	now := time.Now().UTC()
	status := TunnelDesktopStatusOffline
	deviceName := normalizeDeviceName(req.DeviceName)
	_, err := s.db.Exec(`
INSERT INTO TUNNEL_DESKTOP_(DEVICE_ID_, DEVICE_NAME_, USERNAME_, AGENT_TOKEN_BCRYPT_, STATUS_, ENABLED_, PUBLIC_HOST_, PUBLIC_URL_, WEB_SOCKET_URL_, CURRENT_SESSION_ID_, CONNECTED_AT_, LAST_SEEN_AT_, LAST_DISCONNECTED_AT_, BYTES_IN_, BYTES_OUT_, CREATE_AT_, UPDATE_AT_)
VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, NULL, ?, NULL, 0, 0, ?, ?)
ON CONFLICT(DEVICE_ID_) DO UPDATE SET
  DEVICE_NAME_ = excluded.DEVICE_NAME_,
  USERNAME_ = excluded.USERNAME_,
  AGENT_TOKEN_BCRYPT_ = excluded.AGENT_TOKEN_BCRYPT_,
  STATUS_ = CASE WHEN TUNNEL_DESKTOP_.ENABLED_ = 0 THEN TUNNEL_DESKTOP_.STATUS_ ELSE ? END,
  PUBLIC_HOST_ = excluded.PUBLIC_HOST_,
  PUBLIC_URL_ = excluded.PUBLIC_URL_,
  WEB_SOCKET_URL_ = excluded.WEB_SOCKET_URL_,
  LAST_SEEN_AT_ = excluded.LAST_SEEN_AT_,
  UPDATE_AT_ = excluded.UPDATE_AT_`,
		strings.TrimSpace(req.DeviceID),
		deviceName,
		strings.TrimSpace(req.Username),
		req.AgentTokenBcrypt,
		status,
		strings.TrimSpace(req.PublicHost),
		strings.TrimSpace(req.PublicURL),
		strings.TrimSpace(req.WebSocketURL),
		now,
		now,
		now,
		status,
	)
	if err != nil {
		return nil, err
	}
	return s.FindTunnelDesktopByID(req.DeviceID)
}

func (s *Store) ListTunnelDesktops(keyword, status string) ([]TunnelDesktop, error) {
	where, args := tunnelListWhere(keyword, status, []string{"DEVICE_ID_", "DEVICE_NAME_", "USERNAME_", "PUBLIC_HOST_"})
	query := `SELECT DEVICE_ID_, DEVICE_NAME_, USERNAME_, STATUS_, ENABLED_, PUBLIC_HOST_, PUBLIC_URL_, WEB_SOCKET_URL_, CURRENT_SESSION_ID_, CONNECTED_AT_, LAST_SEEN_AT_, LAST_DISCONNECTED_AT_, BYTES_IN_, BYTES_OUT_, CREATE_AT_, UPDATE_AT_ FROM TUNNEL_DESKTOP_`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY UPDATE_AT_ DESC, DEVICE_NAME_ ASC"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TunnelDesktop, 0)
	for rows.Next() {
		desktop, err := scanTunnelDesktop(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *desktop)
	}
	return out, rows.Err()
}

func (s *Store) CloseTunnelDesktop(deviceID string) (*TunnelDesktop, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
UPDATE TUNNEL_DESKTOP_
SET STATUS_ = CASE WHEN ENABLED_ = 0 THEN ? ELSE ? END,
    CURRENT_SESSION_ID_ = NULL,
    CONNECTED_AT_ = NULL,
    LAST_DISCONNECTED_AT_ = ?,
    UPDATE_AT_ = ?
WHERE DEVICE_ID_ = ?`,
		TunnelDesktopStatusDisabled,
		TunnelDesktopStatusOffline,
		now,
		now,
		strings.TrimSpace(deviceID),
	)
	if err != nil {
		return nil, err
	}
	return s.FindTunnelDesktopByID(deviceID)
}

func (s *Store) SetTunnelDesktopEnabled(deviceID string, enabled bool) (*TunnelDesktop, error) {
	now := time.Now().UTC()
	status := TunnelDesktopStatusOffline
	enabledValue := 1
	if !enabled {
		status = TunnelDesktopStatusDisabled
		enabledValue = 0
	}
	_, err := s.db.Exec(`
UPDATE TUNNEL_DESKTOP_
SET ENABLED_ = ?,
    STATUS_ = ?,
    CURRENT_SESSION_ID_ = NULL,
    CONNECTED_AT_ = CASE WHEN ? = 0 THEN NULL ELSE CONNECTED_AT_ END,
    LAST_DISCONNECTED_AT_ = CASE WHEN ? = 0 THEN ? ELSE LAST_DISCONNECTED_AT_ END,
    UPDATE_AT_ = ?
WHERE DEVICE_ID_ = ?`,
		enabledValue,
		status,
		enabledValue,
		enabledValue,
		now,
		now,
		strings.TrimSpace(deviceID),
	)
	if err != nil {
		return nil, err
	}
	return s.FindTunnelDesktopByID(deviceID)
}

func (s *Store) ListTunnelWebapps(keyword, status string) ([]TunnelWebapp, error) {
	where, args := tunnelListWhere(keyword, status, []string{"ROUTE_ID_", "NAME_", "PUBLIC_HOST_", "UPSTREAM_URL_"})
	query := `SELECT ROUTE_ID_, NAME_, PUBLIC_HOST_, PUBLIC_URL_, UPSTREAM_URL_, STATUS_, ENABLED_, CONNECTIONS_, LAST_ACCESSED_AT_, BYTES_IN_, BYTES_OUT_, CREATE_AT_, UPDATE_AT_ FROM TUNNEL_WEBAPP_`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY UPDATE_AT_ DESC, NAME_ ASC"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TunnelWebapp, 0)
	for rows.Next() {
		webapp, err := scanTunnelWebapp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *webapp)
	}
	return out, rows.Err()
}

func (s *Store) RecordTunnelActivity(input TunnelActivityCreate) error {
	if strings.TrimSpace(input.EventType) == "" {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO TUNNEL_ACTIVITY_(ACTIVITY_ID_, OBJECT_TYPE_, OBJECT_ID_, EVENT_TYPE_, ACTOR_, MESSAGE_, BYTES_IN_, BYTES_OUT_, CREATE_AT_) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(),
		strings.TrimSpace(input.ObjectType),
		strings.TrimSpace(input.ObjectID),
		strings.TrimSpace(input.EventType),
		strings.TrimSpace(input.Actor),
		strings.TrimSpace(input.Message),
		input.BytesIn,
		input.BytesOut,
		now,
	)
	return err
}

func (s *Store) ListTunnelActivities(keyword, objectType string, limit int) ([]TunnelActivity, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	where := make([]string, 0)
	args := make([]any, 0)
	if typ := strings.TrimSpace(objectType); typ != "" && !strings.EqualFold(typ, "ALL") {
		where = append(where, "OBJECT_TYPE_ = ?")
		args = append(args, typ)
	}
	if q := strings.TrimSpace(keyword); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		where = append(where, "(LOWER(OBJECT_ID_) LIKE ? OR LOWER(EVENT_TYPE_) LIKE ? OR LOWER(ACTOR_) LIKE ? OR LOWER(MESSAGE_) LIKE ?)")
		args = append(args, like, like, like, like)
	}
	query := `SELECT ACTIVITY_ID_, OBJECT_TYPE_, OBJECT_ID_, EVENT_TYPE_, ACTOR_, MESSAGE_, BYTES_IN_, BYTES_OUT_, CREATE_AT_ FROM TUNNEL_ACTIVITY_`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY CREATE_AT_ DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TunnelActivity, 0)
	for rows.Next() {
		activity, err := scanTunnelActivity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *activity)
	}
	return out, rows.Err()
}

func (s *Store) AggregateTunnelTraffic(bucket string, since time.Time, limit int) ([]TunnelTrafficPoint, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 720 {
		limit = 720
	}
	expr := "strftime('%Y-%m-%dT%H:00:00Z', BUCKET_START_)"
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "day":
		expr = "strftime('%Y-%m-%dT00:00:00Z', BUCKET_START_)"
	case "month":
		expr = "strftime('%Y-%m-01T00:00:00Z', BUCKET_START_)"
	}
	query := fmt.Sprintf(`
SELECT %s AS BUCKET_,
       SUM(CASE WHEN BUCKET_KIND_ = 'desktop' THEN BYTES_IN_ ELSE 0 END),
       SUM(CASE WHEN BUCKET_KIND_ = 'desktop' THEN BYTES_OUT_ ELSE 0 END),
       SUM(CASE WHEN BUCKET_KIND_ = 'webapp' THEN BYTES_IN_ ELSE 0 END),
       SUM(CASE WHEN BUCKET_KIND_ = 'webapp' THEN BYTES_OUT_ ELSE 0 END)
FROM TUNNEL_TRAFFIC_BUCKET_
WHERE BUCKET_START_ >= ?
GROUP BY BUCKET_
ORDER BY BUCKET_ ASC
LIMIT ?`, expr)
	rows, err := s.db.Query(query, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TunnelTrafficPoint, 0)
	for rows.Next() {
		var (
			rawBucket string
			point     TunnelTrafficPoint
		)
		if err := rows.Scan(&rawBucket, &point.DesktopBytesIn, &point.DesktopBytesOut, &point.WebappBytesIn, &point.WebappBytesOut); err != nil {
			return nil, err
		}
		bucketStart, err := time.Parse(time.RFC3339, rawBucket)
		if err != nil {
			return nil, err
		}
		point.BucketStart = bucketStart.UTC()
		out = append(out, point)
	}
	return out, rows.Err()
}

func tunnelListWhere(keyword, status string, columns []string) ([]string, []any) {
	where := make([]string, 0)
	args := make([]any, 0)
	if st := strings.TrimSpace(status); st != "" && !strings.EqualFold(st, "ALL") {
		where = append(where, "STATUS_ = ?")
		args = append(args, strings.ToUpper(st))
	}
	if q := strings.TrimSpace(keyword); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		parts := make([]string, 0, len(columns))
		for _, column := range columns {
			parts = append(parts, "LOWER("+column+") LIKE ?")
			args = append(args, like)
		}
		where = append(where, "("+strings.Join(parts, " OR ")+")")
	}
	return where, args
}

func scanTunnelDesktop(scanner interface{ Scan(dest ...any) error }) (*TunnelDesktop, error) {
	var (
		rec                                   TunnelDesktop
		enabled                               int
		currentSession                        sql.NullString
		connectedAt, lastSeen, disconnectedAt sql.NullTime
	)
	if err := scanner.Scan(&rec.DeviceID, &rec.DeviceName, &rec.Username, &rec.Status, &enabled, &rec.PublicHost, &rec.PublicURL, &rec.WebSocketURL, &currentSession, &connectedAt, &lastSeen, &disconnectedAt, &rec.BytesIn, &rec.BytesOut, &rec.CreateAt, &rec.UpdateAt); err != nil {
		return nil, err
	}
	rec.Enabled = enabled == 1
	if currentSession.Valid {
		rec.CurrentSessionID = currentSession.String
	}
	rec.ConnectedAt = nullTimePtr(connectedAt)
	rec.LastSeenAt = nullTimePtr(lastSeen)
	rec.LastDisconnectedAt = nullTimePtr(disconnectedAt)
	rec.CreateAt = rec.CreateAt.UTC()
	rec.UpdateAt = rec.UpdateAt.UTC()
	return &rec, nil
}

func scanTunnelWebapp(scanner interface{ Scan(dest ...any) error }) (*TunnelWebapp, error) {
	var (
		rec          TunnelWebapp
		enabled      int
		lastAccessed sql.NullTime
	)
	if err := scanner.Scan(&rec.RouteID, &rec.Name, &rec.PublicHost, &rec.PublicURL, &rec.UpstreamURL, &rec.Status, &enabled, &rec.Connections, &lastAccessed, &rec.BytesIn, &rec.BytesOut, &rec.CreateAt, &rec.UpdateAt); err != nil {
		return nil, err
	}
	rec.Enabled = enabled == 1
	rec.LastAccessedAt = nullTimePtr(lastAccessed)
	rec.CreateAt = rec.CreateAt.UTC()
	rec.UpdateAt = rec.UpdateAt.UTC()
	return &rec, nil
}

func scanTunnelActivity(scanner interface{ Scan(dest ...any) error }) (*TunnelActivity, error) {
	var rec TunnelActivity
	if err := scanner.Scan(&rec.ActivityID, &rec.ObjectType, &rec.ObjectID, &rec.EventType, &rec.Actor, &rec.Message, &rec.BytesIn, &rec.BytesOut, &rec.CreateAt); err != nil {
		return nil, err
	}
	rec.CreateAt = rec.CreateAt.UTC()
	return &rec, nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}
