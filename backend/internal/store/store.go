package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type User struct {
	UserID       string `json:"userId"`
	Username     string `json:"username"`
	PasswordHash string
	DisplayName  string    `json:"displayName"`
	Status       string    `json:"status"`
	CreateAt     time.Time `json:"createAt"`
	UpdateAt     time.Time `json:"updateAt"`
}

type OAuthClient struct {
	ID             string   `json:"id"`
	ClientID       string   `json:"clientId"`
	ClientName     string   `json:"clientName"`
	GrantTypes     []string `json:"grantTypes"`
	RedirectURIs   []string `json:"redirectUris"`
	Scopes         []string `json:"scopes"`
	RequirePKCE    bool     `json:"requirePkce"`
	Status         string   `json:"status"`
	ClientSecret   string
	CreateAt       time.Time `json:"createAt"`
	UpdateAt       time.Time `json:"updateAt"`
	AuthMethods    []string
	TokenSettings  map[string]any
	ClientSettings map[string]any
}

type Device struct {
	DeviceID          string     `json:"deviceId"`
	DeviceName        string     `json:"deviceName"`
	DeviceTokenBcrypt string     `json:"-"`
	Status            string     `json:"status"`
	LastSeenAt        *time.Time `json:"lastSeenAt"`
	RevokedAt         *time.Time `json:"revokedAt"`
	CreateAt          time.Time  `json:"createAt"`
	UpdateAt          time.Time  `json:"updateAt"`
}

type TokenAudit struct {
	TokenID         string     `json:"tokenId"`
	Source          string     `json:"source"`
	Token           string     `json:"token"`
	TokenSHA256     string     `json:"tokenSha256"`
	Username        *string    `json:"username"`
	DeviceID        *string    `json:"deviceId"`
	DeviceName      *string    `json:"deviceName"`
	ClientID        *string    `json:"clientId"`
	AuthorizationID *string    `json:"authorizationId"`
	IssuedAt        time.Time  `json:"issuedAt"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	RevokedAt       *time.Time `json:"revokedAt"`
	CreateAt        time.Time
	UpdateAt        time.Time
}

type OAuthAuthorization struct {
	ID                         string
	RegisteredClientID         string
	PrincipalName              string
	AuthorizationGrantType     string
	AuthorizedScopes           string
	Attributes                 []byte
	State                      sql.NullString
	AuthorizationCodeValue     []byte
	AuthorizationCodeIssuedAt  sql.NullTime
	AuthorizationCodeExpiresAt sql.NullTime
	AccessTokenValue           []byte
	AccessTokenIssuedAt        sql.NullTime
	AccessTokenExpiresAt       sql.NullTime
	AccessTokenType            sql.NullString
	AccessTokenScopes          sql.NullString
	RefreshTokenValue          []byte
	RefreshTokenIssuedAt       sql.NullTime
	RefreshTokenExpiresAt      sql.NullTime
}

func (s *Store) FindUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(`SELECT USER_ID_, USERNAME_, PASSWORD_BCRYPT_, DISPLAY_NAME_, STATUS_, CREATE_AT_, UPDATE_AT_ FROM APP_USER_ WHERE USERNAME_ = ?`, username)
	return scanUser(row)
}

func (s *Store) FindUserByID(userID string) (*User, error) {
	row := s.db.QueryRow(`SELECT USER_ID_, USERNAME_, PASSWORD_BCRYPT_, DISPLAY_NAME_, STATUS_, CREATE_AT_, UPDATE_AT_ FROM APP_USER_ WHERE USER_ID_ = ?`, userID)
	return scanUser(row)
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT USER_ID_, USERNAME_, PASSWORD_BCRYPT_, DISPLAY_NAME_, STATUS_, CREATE_AT_, UPDATE_AT_ FROM APP_USER_ ORDER BY CREATE_AT_ DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Status, &u.CreateAt, &u.UpdateAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(username, password, displayName, status string) (*User, error) {
	if status == "" {
		status = "ACTIVE"
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO APP_USER_(USER_ID_, USERNAME_, PASSWORD_BCRYPT_, DISPLAY_NAME_, STATUS_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, ?, ?, ?, ?)`, id, strings.TrimSpace(username), string(hash), strings.TrimSpace(displayName), status, now, now)
	if err != nil {
		return nil, err
	}
	return s.FindUserByID(id)
}

func (s *Store) UpdateUser(userID, displayName, status string) (*User, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE APP_USER_ SET DISPLAY_NAME_ = ?, STATUS_ = ?, UPDATE_AT_ = ? WHERE USER_ID_ = ?`, strings.TrimSpace(displayName), status, now, userID)
	if err != nil {
		return nil, err
	}
	return s.FindUserByID(userID)
}

func (s *Store) PatchUserStatus(userID, status string) (*User, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE APP_USER_ SET STATUS_ = ?, UPDATE_AT_ = ? WHERE USER_ID_ = ?`, status, now, userID)
	if err != nil {
		return nil, err
	}
	return s.FindUserByID(userID)
}

func (s *Store) ResetUserPassword(userID, password string) error {
	now := time.Now().UTC()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE APP_USER_ SET PASSWORD_BCRYPT_ = ?, UPDATE_AT_ = ? WHERE USER_ID_ = ?`, string(hash), now, userID)
	return err
}

func (s *Store) ListClients() ([]OAuthClient, error) {
	rows, err := s.db.Query(`SELECT ID_, CLIENT_ID_, CLIENT_SECRET_, CLIENT_NAME_, AUTH_GRANT_TYPES_, REDIRECT_URIS_, SCOPES_, REQUIRE_PKCE_, STATUS_, CLIENT_AUTH_METHODS_, CLIENT_SETTINGS_, TOKEN_SETTINGS_, CREATE_AT_, UPDATE_AT_ FROM OAUTH2_CLIENT_ ORDER BY CREATE_AT_ DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]OAuthClient, 0)
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *client)
	}
	return out, rows.Err()
}

func (s *Store) FindClient(clientID string) (*OAuthClient, error) {
	rows, err := s.db.Query(`SELECT ID_, CLIENT_ID_, CLIENT_SECRET_, CLIENT_NAME_, AUTH_GRANT_TYPES_, REDIRECT_URIS_, SCOPES_, REQUIRE_PKCE_, STATUS_, CLIENT_AUTH_METHODS_, CLIENT_SETTINGS_, TOKEN_SETTINGS_, CREATE_AT_, UPDATE_AT_ FROM OAUTH2_CLIENT_ WHERE CLIENT_ID_ = ? LIMIT 1`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	client, err := scanClient(rows)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Store) FindActiveClient(clientID string) (*OAuthClient, error) {
	client, err := s.FindClient(clientID)
	if err != nil {
		return nil, err
	}
	if client.Status != "ACTIVE" {
		return nil, sql.ErrNoRows
	}
	return client, nil
}

func (s *Store) FindClientByInternalID(id string) (*OAuthClient, error) {
	rows, err := s.db.Query(`SELECT ID_, CLIENT_ID_, CLIENT_SECRET_, CLIENT_NAME_, AUTH_GRANT_TYPES_, REDIRECT_URIS_, SCOPES_, REQUIRE_PKCE_, STATUS_, CLIENT_AUTH_METHODS_, CLIENT_SETTINGS_, TOKEN_SETTINGS_, CREATE_AT_, UPDATE_AT_ FROM OAUTH2_CLIENT_ WHERE ID_ = ? LIMIT 1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanClient(rows)
}

func (s *Store) CreateClient(req OAuthClientCreateRequest) (*OAuthClient, error) {
	if req.Status == "" {
		req.Status = "ACTIVE"
	}
	if req.RequirePKCE == nil {
		value := true
		req.RequirePKCE = &value
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	secretHash := ""
	if strings.TrimSpace(req.ClientSecret) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.ClientSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		secretHash = string(hash)
	}
	authMethods := []string{"none"}
	if secretHash != "" {
		authMethods = []string{"client_secret_basic", "client_secret_post"}
	}
	clientSettings := map[string]any{
		"settings.client.require-proof-key":             *req.RequirePKCE,
		"settings.client.require-authorization-consent": true,
	}
	tokenSettings := map[string]any{
		"settings.token.reuse-refresh-tokens": !req.RotateRefreshToken,
	}
	clientSettingsRaw, _ := json.Marshal(clientSettings)
	tokenSettingsRaw, _ := json.Marshal(tokenSettings)
	_, err := s.db.Exec(`INSERT INTO OAUTH2_CLIENT_(ID_, CLIENT_ID_, CLIENT_ID_ISSUED_AT_, CLIENT_SECRET_, CLIENT_SECRET_EXPIRES_AT_, CLIENT_NAME_, CLIENT_AUTH_METHODS_, AUTH_GRANT_TYPES_, REDIRECT_URIS_, POST_LOGOUT_REDIRECT_URIS_, SCOPES_, CLIENT_SETTINGS_, TOKEN_SETTINGS_, REQUIRE_PKCE_, STATUS_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		strings.TrimSpace(req.ClientID),
		now,
		secretHash,
		strings.TrimSpace(req.ClientName),
		joinCSV(authMethods),
		joinCSV(req.GrantTypes),
		joinCSV(req.RedirectURIs),
		"",
		joinCSV(req.Scopes),
		string(clientSettingsRaw),
		string(tokenSettingsRaw),
		boolToInt(*req.RequirePKCE),
		req.Status,
		now,
		now,
	)
	if err != nil {
		return nil, err
	}
	return s.FindClient(req.ClientID)
}

type OAuthClientCreateRequest struct {
	ClientID           string
	ClientName         string
	ClientSecret       string
	GrantTypes         []string
	RedirectURIs       []string
	Scopes             []string
	RequirePKCE        *bool
	Status             string
	RotateRefreshToken bool
}

func (s *Store) UpdateClient(clientID string, req OAuthClientUpdateRequest) (*OAuthClient, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE OAUTH2_CLIENT_ SET CLIENT_NAME_ = ?, AUTH_GRANT_TYPES_ = ?, REDIRECT_URIS_ = ?, SCOPES_ = ?, REQUIRE_PKCE_ = ?, STATUS_ = ?, UPDATE_AT_ = ? WHERE CLIENT_ID_ = ?`,
		strings.TrimSpace(req.ClientName),
		joinCSV(req.GrantTypes),
		joinCSV(req.RedirectURIs),
		joinCSV(req.Scopes),
		boolToInt(req.RequirePKCE),
		req.Status,
		now,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	return s.FindClient(clientID)
}

type OAuthClientUpdateRequest struct {
	ClientName   string
	GrantTypes   []string
	RedirectURIs []string
	Scopes       []string
	RequirePKCE  bool
	Status       string
}

func (s *Store) PatchClientStatus(clientID, status string) (*OAuthClient, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE OAUTH2_CLIENT_ SET STATUS_ = ?, UPDATE_AT_ = ? WHERE CLIENT_ID_ = ?`, status, now, clientID)
	if err != nil {
		return nil, err
	}
	return s.FindClient(clientID)
}

func (s *Store) RotateClientSecret(clientID string) (string, error) {
	rawSecret := strings.ReplaceAll(uuid.NewString(), "-", "")
	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`UPDATE OAUTH2_CLIENT_ SET CLIENT_SECRET_ = ?, CLIENT_AUTH_METHODS_ = ?, UPDATE_AT_ = ? WHERE CLIENT_ID_ = ?`, string(hash), "client_secret_basic,client_secret_post", time.Now().UTC(), clientID)
	if err != nil {
		return "", err
	}
	return rawSecret, nil
}

func (s *Store) EnsureBootstrapClient() error {
	row := s.db.QueryRow(`SELECT COUNT(*) FROM OAUTH2_CLIENT_ WHERE CLIENT_ID_ = 'mobile-app'`)
	var count int
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	req := OAuthClientCreateRequest{
		ClientID:           "mobile-app",
		ClientName:         "Mobile App",
		GrantTypes:         []string{"authorization_code", "refresh_token"},
		RedirectURIs:       []string{"myapp://oauthredirect"},
		Scopes:             []string{"openid", "profile"},
		RequirePKCE:        boolPtr(true),
		Status:             "ACTIVE",
		RotateRefreshToken: true,
	}
	_, err := s.CreateClient(req)
	return err
}

func (s *Store) CreateDevice(name, rawToken string) (*Device, error) {
	id := uuid.NewString()
	now := time.Now().UTC()
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	deviceName := strings.TrimSpace(name)
	if deviceName == "" {
		deviceName = "Unknown Device"
	}
	deviceName = normalizeDeviceName(deviceName)
	_, err = s.db.Exec(`INSERT INTO DEVICE_(DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, 'ACTIVE', ?, NULL, ?, ?)`, id, deviceName, string(tokenHash), now, now, now)
	if err != nil {
		return nil, err
	}
	return s.FindDeviceByID(id)
}

func (s *Store) EnsureActiveDeviceWithHash(name, tokenHash string) (*Device, error) {
	deviceName := normalizeDeviceName(name)
	row := s.db.QueryRow(`SELECT DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM DEVICE_ WHERE ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE' AND DEVICE_NAME_ = ? ORDER BY UPDATE_AT_ DESC LIMIT 1`, deviceName)
	device, err := scanDevice(row)
	if err == nil {
		now := time.Now().UTC()
		if _, touchErr := s.db.Exec(`UPDATE DEVICE_ SET LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, now, now, device.DeviceID); touchErr != nil {
			return nil, touchErr
		}
		return s.FindDeviceByID(device.DeviceID)
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO DEVICE_(DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, 'ACTIVE', ?, NULL, ?, ?)`, id, deviceName, tokenHash, now, now, now)
	if err != nil {
		return nil, err
	}
	return s.FindDeviceByID(id)
}

func (s *Store) EnsureActiveDeviceWithID(deviceID, name, tokenHash string) (*Device, error) {
	deviceID = strings.TrimSpace(deviceID)
	deviceName := normalizeDeviceName(name)
	device, err := s.FindDeviceByID(deviceID)
	if err == nil {
		if device.Status != "ACTIVE" {
			return nil, fmt.Errorf("device %s is not active", deviceID)
		}
		now := time.Now().UTC()
		if _, touchErr := s.db.Exec(`UPDATE DEVICE_ SET LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, now, now, device.DeviceID); touchErr != nil {
			return nil, touchErr
		}
		return s.FindDeviceByID(device.DeviceID)
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO DEVICE_(DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, 'ACTIVE', ?, NULL, ?, ?)`, deviceID, deviceName, tokenHash, now, now, now)
	if err != nil {
		return nil, err
	}
	return s.FindDeviceByID(deviceID)
}

func normalizeDeviceName(name string) string {
	deviceName := strings.TrimSpace(name)
	if deviceName == "" {
		deviceName = "Unknown Device"
	}
	runes := []rune(deviceName)
	if len(runes) > 64 {
		deviceName = string(runes[:64])
	}
	return deviceName
}

func (s *Store) FindDeviceByID(deviceID string) (*Device, error) {
	row := s.db.QueryRow(`SELECT DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM DEVICE_ WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = ''`, deviceID)
	return scanDevice(row)
}

func (s *Store) FindActiveDeviceByToken(rawToken string) (*Device, error) {
	rows, err := s.db.Query(`SELECT DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM DEVICE_ WHERE ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE' ORDER BY UPDATE_AT_ DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		if bcrypt.CompareHashAndPassword([]byte(device.DeviceTokenBcrypt), []byte(rawToken)) == nil {
			return device, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM DEVICE_ WHERE ACCOUNT_ID_ = '' ORDER BY UPDATE_AT_ DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Device, 0)
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *device)
	}
	return result, rows.Err()
}

func (s *Store) TouchDevice(deviceID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE DEVICE_ SET LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, now, now, deviceID)
	return err
}

func (s *Store) RenameDevice(deviceID, name string) error {
	now := time.Now().UTC()
	deviceName := strings.TrimSpace(name)
	if deviceName == "" {
		return fmt.Errorf("deviceName is required")
	}
	deviceName = normalizeDeviceName(deviceName)
	_, err := s.db.Exec(`UPDATE DEVICE_ SET DEVICE_NAME_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = ''`, deviceName, now, deviceID)
	return err
}

func (s *Store) RevokeDevice(deviceID string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE DEVICE_ SET STATUS_ = 'REVOKED', REVOKED_AT_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, now, now, deviceID)
	return err
}

func (s *Store) RotateDeviceToken(deviceID, rawToken string) error {
	now := time.Now().UTC()
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE DEVICE_ SET DEVICE_TOKEN_BCRYPT_ = ?, LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, string(hash), now, now, deviceID)
	return err
}

func (s *Store) IsDeviceActive(deviceID string) (bool, error) {
	row := s.db.QueryRow(`SELECT COUNT(*) FROM DEVICE_ WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ = '' AND STATUS_ = 'ACTIVE'`, deviceID)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) DeleteRevokedDevicesOlderThan(retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	res, err := s.db.Exec(`DELETE FROM DEVICE_ WHERE STATUS_ = 'REVOKED' AND UPDATE_AT_ < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) RecordTokenAudit(source, token string, username, deviceID, deviceName, clientID, authorizationID *string, issuedAt time.Time, expiresAt *time.Time) error {
	if strings.TrimSpace(source) == "" || strings.TrimSpace(token) == "" {
		return nil
	}
	tokenValue := token
	if source == "ACCOUNT_APP_ACCESS" {
		tokenValue = ""
	}
	tokenSHA256 := sha256Hex(token)
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO TOKEN_AUDIT_(TOKEN_ID_, SOURCE_, TOKEN_VALUE_, TOKEN_SHA256_, USERNAME_, DEVICE_ID_, DEVICE_NAME_, CLIENT_ID_, AUTHORIZATION_ID_, ISSUED_AT_, EXPIRES_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?) ON CONFLICT(TOKEN_SHA256_) DO UPDATE SET SOURCE_=excluded.SOURCE_, TOKEN_VALUE_=excluded.TOKEN_VALUE_, USERNAME_=excluded.USERNAME_, DEVICE_ID_=excluded.DEVICE_ID_, DEVICE_NAME_=excluded.DEVICE_NAME_, CLIENT_ID_=excluded.CLIENT_ID_, AUTHORIZATION_ID_=excluded.AUTHORIZATION_ID_, ISSUED_AT_=excluded.ISSUED_AT_, EXPIRES_AT_=excluded.EXPIRES_AT_, UPDATE_AT_=excluded.UPDATE_AT_`,
		uuid.NewString(), strings.ToUpper(source), tokenValue, tokenSHA256, nullable(username), nullable(deviceID), nullable(deviceName), nullable(clientID), nullable(authorizationID), issuedAt.UTC(), timePtrValue(expiresAt), now, now)
	return err
}

func (s *Store) MarkTokensRevokedByDeviceID(deviceID string) error {
	if strings.TrimSpace(deviceID) == "" {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE TOKEN_AUDIT_ SET REVOKED_AT_ = COALESCE(REVOKED_AT_, ?), UPDATE_AT_ = ? WHERE DEVICE_ID_ = ? AND REVOKED_AT_ IS NULL`, now, now, deviceID)
	return err
}

func (s *Store) MarkTokensRevokedByAuthorizationID(authorizationID string) error {
	if strings.TrimSpace(authorizationID) == "" {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE TOKEN_AUDIT_ SET REVOKED_AT_ = COALESCE(REVOKED_AT_, ?), UPDATE_AT_ = ? WHERE AUTHORIZATION_ID_ = ? AND REVOKED_AT_ IS NULL`, now, now, authorizationID)
	return err
}

func (s *Store) ListTokenAudits(sources []string, status string, limit int) ([]TokenAudit, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	where := make([]string, 0)
	args := make([]any, 0)
	if len(sources) > 0 {
		placeholders := make([]string, 0, len(sources))
		for _, src := range sources {
			placeholders = append(placeholders, "?")
			args = append(args, strings.ToUpper(strings.TrimSpace(src)))
		}
		where = append(where, fmt.Sprintf("SOURCE_ IN (%s)", strings.Join(placeholders, ",")))
	}
	now := time.Now().UTC()
	switch strings.ToUpper(status) {
	case "ACTIVE":
		where = append(where, "REVOKED_AT_ IS NULL", "(EXPIRES_AT_ IS NULL OR EXPIRES_AT_ > ?)")
		args = append(args, now)
	case "EXPIRED":
		where = append(where, "REVOKED_AT_ IS NULL", "EXPIRES_AT_ IS NOT NULL", "EXPIRES_AT_ <= ?")
		args = append(args, now)
	case "REVOKED":
		where = append(where, "REVOKED_AT_ IS NOT NULL")
	}
	query := `SELECT TOKEN_ID_, SOURCE_, TOKEN_VALUE_, TOKEN_SHA256_, USERNAME_, DEVICE_ID_, DEVICE_NAME_, CLIENT_ID_, AUTHORIZATION_ID_, ISSUED_AT_, EXPIRES_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM TOKEN_AUDIT_`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY ISSUED_AT_ DESC, CREATE_AT_ DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TokenAudit, 0)
	for rows.Next() {
		rec, err := scanTokenAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTokenAuditIssuedOlderThan(retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	res, err := s.db.Exec(`DELETE FROM TOKEN_AUDIT_ WHERE ISSUED_AT_ < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) SaveOAuthCode(record OAuthAuthorization) error {
	_, err := s.db.Exec(`INSERT INTO oauth2_authorization(id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.RegisteredClientID,
		record.PrincipalName,
		record.AuthorizationGrantType,
		record.AuthorizedScopes,
		record.Attributes,
		record.State,
		record.AuthorizationCodeValue,
		record.AuthorizationCodeIssuedAt,
		record.AuthorizationCodeExpiresAt,
		[]byte("{}"),
	)
	return err
}

func (s *Store) FindOAuthByCode(code string) (*OAuthAuthorization, error) {
	rows, err := s.db.Query(`SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, access_token_value, access_token_issued_at, access_token_expires_at, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at FROM oauth2_authorization WHERE authorization_code_value = ? LIMIT 1`, []byte(code))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanOAuthAuthorization(rows)
}

func (s *Store) FindOAuthByRefreshToken(token string) (*OAuthAuthorization, error) {
	rows, err := s.db.Query(`SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, access_token_value, access_token_issued_at, access_token_expires_at, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at FROM oauth2_authorization WHERE refresh_token_value = ? LIMIT 1`, []byte(token))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanOAuthAuthorization(rows)
}

func (s *Store) FindOAuthByAccessToken(token string) (*OAuthAuthorization, error) {
	rows, err := s.db.Query(`SELECT id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, access_token_value, access_token_issued_at, access_token_expires_at, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at FROM oauth2_authorization WHERE access_token_value = ? LIMIT 1`, []byte(token))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanOAuthAuthorization(rows)
}

func (s *Store) SaveOAuthTokens(authorizationID, accessToken, refreshToken string, accessIssuedAt, accessExpiresAt, refreshIssuedAt, refreshExpiresAt time.Time, scopes []string) error {
	_, err := s.db.Exec(`UPDATE oauth2_authorization SET access_token_value = ?, access_token_issued_at = ?, access_token_expires_at = ?, access_token_metadata = ?, access_token_type = ?, access_token_scopes = ?, refresh_token_value = ?, refresh_token_issued_at = ?, refresh_token_expires_at = ?, refresh_token_metadata = ? WHERE id = ?`,
		[]byte(accessToken), accessIssuedAt.UTC(), accessExpiresAt.UTC(), []byte("{}"), "Bearer", joinCSV(scopes), []byte(refreshToken), refreshIssuedAt.UTC(), refreshExpiresAt.UTC(), []byte("{}"), authorizationID)
	return err
}

func (s *Store) ReplaceOAuthTokens(authorizationID, accessToken, refreshToken string, accessIssuedAt, accessExpiresAt, refreshIssuedAt, refreshExpiresAt time.Time, scopes []string, rotateRefresh bool) error {
	if rotateRefresh {
		return s.SaveOAuthTokens(authorizationID, accessToken, refreshToken, accessIssuedAt, accessExpiresAt, refreshIssuedAt, refreshExpiresAt, scopes)
	}
	_, err := s.db.Exec(`UPDATE oauth2_authorization SET access_token_value = ?, access_token_issued_at = ?, access_token_expires_at = ?, access_token_metadata = ?, access_token_type = ?, access_token_scopes = ? WHERE id = ?`,
		[]byte(accessToken), accessIssuedAt.UTC(), accessExpiresAt.UTC(), []byte("{}"), "Bearer", joinCSV(scopes), authorizationID)
	return err
}

func (s *Store) RevokeOAuthByToken(token string) error {
	row := s.db.QueryRow(`SELECT id FROM oauth2_authorization WHERE access_token_value = ? OR refresh_token_value = ? LIMIT 1`, []byte(token), []byte(token))
	var id string
	if err := row.Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	_, err := s.db.Exec(`DELETE FROM oauth2_authorization WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return s.MarkTokensRevokedByAuthorizationID(id)
}

func (s *Store) SaveOAuthConsent(clientID, principalName string, authorities []string) error {
	_, err := s.db.Exec(`INSERT INTO oauth2_authorization_consent(registered_client_id, principal_name, authorities) VALUES(?, ?, ?) ON CONFLICT(registered_client_id, principal_name) DO UPDATE SET authorities = excluded.authorities`, clientID, principalName, joinCSV(authorities))
	return err
}

func (s *Store) FindOAuthConsent(clientID, principalName string) ([]string, error) {
	row := s.db.QueryRow(`SELECT authorities FROM oauth2_authorization_consent WHERE registered_client_id = ? AND principal_name = ?`, clientID, principalName)
	var auth sql.NullString
	if err := row.Scan(&auth); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return splitCSV(auth.String), nil
}

func (s *Store) WithTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (*User, error) {
	var u User
	if err := scanner.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Status, &u.CreateAt, &u.UpdateAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func scanClient(scanner interface{ Scan(dest ...any) error }) (*OAuthClient, error) {
	var (
		c                                             OAuthClient
		grantTypes, redirectURIs, scopes, authMethods sql.NullString
		clientSettingsRaw, tokenSettingsRaw           sql.NullString
		requirePkce                                   int
	)
	if err := scanner.Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.ClientName, &grantTypes, &redirectURIs, &scopes, &requirePkce, &c.Status, &authMethods, &clientSettingsRaw, &tokenSettingsRaw, &c.CreateAt, &c.UpdateAt); err != nil {
		return nil, err
	}
	c.RequirePKCE = requirePkce == 1
	c.GrantTypes = splitCSV(grantTypes.String)
	c.RedirectURIs = splitCSV(redirectURIs.String)
	c.Scopes = splitCSV(scopes.String)
	c.AuthMethods = splitCSV(authMethods.String)
	c.ClientSettings = map[string]any{}
	c.TokenSettings = map[string]any{}
	if clientSettingsRaw.Valid {
		_ = json.Unmarshal([]byte(clientSettingsRaw.String), &c.ClientSettings)
	}
	if tokenSettingsRaw.Valid {
		_ = json.Unmarshal([]byte(tokenSettingsRaw.String), &c.TokenSettings)
	}
	return &c, nil
}

func scanDevice(scanner interface{ Scan(dest ...any) error }) (*Device, error) {
	var (
		d        Device
		lastSeen sql.NullTime
		revoked  sql.NullTime
	)
	if err := scanner.Scan(&d.DeviceID, &d.DeviceName, &d.DeviceTokenBcrypt, &d.Status, &lastSeen, &revoked, &d.CreateAt, &d.UpdateAt); err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		t := lastSeen.Time.UTC()
		d.LastSeenAt = &t
	}
	if revoked.Valid {
		t := revoked.Time.UTC()
		d.RevokedAt = &t
	}
	return &d, nil
}

func scanTokenAudit(scanner interface{ Scan(dest ...any) error }) (*TokenAudit, error) {
	var (
		r                                                TokenAudit
		username, deviceID, deviceName, clientID, authID sql.NullString
		expiresAt, revokedAt                             sql.NullTime
	)
	if err := scanner.Scan(&r.TokenID, &r.Source, &r.Token, &r.TokenSHA256, &username, &deviceID, &deviceName, &clientID, &authID, &r.IssuedAt, &expiresAt, &revokedAt, &r.CreateAt, &r.UpdateAt); err != nil {
		return nil, err
	}
	r.Username = nullStringPtr(username)
	r.DeviceID = nullStringPtr(deviceID)
	r.DeviceName = nullStringPtr(deviceName)
	r.ClientID = nullStringPtr(clientID)
	r.AuthorizationID = nullStringPtr(authID)
	if expiresAt.Valid {
		t := expiresAt.Time.UTC()
		r.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		r.RevokedAt = &t
	}
	return &r, nil
}

func scanOAuthAuthorization(scanner interface{ Scan(dest ...any) error }) (*OAuthAuthorization, error) {
	var rec OAuthAuthorization
	if err := scanner.Scan(
		&rec.ID,
		&rec.RegisteredClientID,
		&rec.PrincipalName,
		&rec.AuthorizationGrantType,
		&rec.AuthorizedScopes,
		&rec.Attributes,
		&rec.State,
		&rec.AuthorizationCodeValue,
		&rec.AuthorizationCodeIssuedAt,
		&rec.AuthorizationCodeExpiresAt,
		&rec.AccessTokenValue,
		&rec.AccessTokenIssuedAt,
		&rec.AccessTokenExpiresAt,
		&rec.AccessTokenType,
		&rec.AccessTokenScopes,
		&rec.RefreshTokenValue,
		&rec.RefreshTokenIssuedAt,
		&rec.RefreshTokenExpiresAt,
	); err != nil {
		return nil, err
	}
	return &rec, nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func joinCSV(values []string) string {
	clean := make([]string, 0, len(values))
	for _, v := range values {
		if item := strings.TrimSpace(v); item != "" {
			clean = append(clean, item)
		}
	}
	return strings.Join(clean, ",")
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func boolPtr(v bool) *bool {
	return &v
}

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return nil
	}
	x := v.String
	return &x
}

func nullable(v *string) any {
	if v == nil || strings.TrimSpace(*v) == "" {
		return nil
	}
	return strings.TrimSpace(*v)
}

func timePtrValue(v *time.Time) any {
	if v == nil {
		return nil
	}
	return v.UTC()
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}
