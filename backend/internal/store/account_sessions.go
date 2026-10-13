package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AccountSession struct {
	Device
	AccountID string
}

type CreateAccountSessionResult struct {
	Session     AccountSession
	DeviceToken string
}

// ValidAccountSessionName checks the display name shared by all account login methods.
func ValidAccountSessionName(name string) bool {
	name = strings.TrimSpace(name)
	return name != "" && len([]rune(name)) <= 64
}

func randomAuthSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func prepareAccountSession(accountID, name string) (CreateAccountSessionResult, error) {
	name = strings.TrimSpace(name)
	if accountID == "" || !ValidAccountSessionName(name) {
		return CreateAccountSessionResult{}, errors.New("invalid account session")
	}
	id := uuid.NewString()
	secret, err := randomAuthSecret()
	if err != nil {
		return CreateAccountSessionResult{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return CreateAccountSessionResult{}, err
	}
	now := time.Now().UTC()
	return CreateAccountSessionResult{Session: AccountSession{AccountID: accountID, Device: Device{DeviceID: id, DeviceName: name, DeviceTokenBcrypt: string(hash), Status: "ACTIVE", LastSeenAt: &now, CreateAt: now, UpdateAt: now}}, DeviceToken: id + "." + secret}, nil
}
func insertAccountSession(executor interface {
	Exec(string, ...any) (sql.Result, error)
}, session AccountSession) error {
	_, err := executor.Exec(`INSERT INTO DEVICE_(DEVICE_ID_, ACCOUNT_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, ?, 'ACTIVE', ?, ?, ?)`, session.DeviceID, session.AccountID, session.DeviceName, session.DeviceTokenBcrypt, session.LastSeenAt, session.CreateAt, session.UpdateAt)
	return err
}
func (s *Store) CreateAccountSession(accountID, name string) (CreateAccountSessionResult, error) {
	created, err := prepareAccountSession(accountID, name)
	if err != nil {
		return created, err
	}
	err = insertAccountSession(s.db, created.Session)
	return created, err
}

func (s *Store) FindAccountSessionByID(accountID, id string) (*AccountSession, error) {
	// Reuse the legacy row scanner without widening the legacy device namespace.
	row := s.db.QueryRow(`SELECT DEVICE_ID_, DEVICE_NAME_, DEVICE_TOKEN_BCRYPT_, STATUS_, LAST_SEEN_AT_, REVOKED_AT_, CREATE_AT_, UPDATE_AT_ FROM DEVICE_ WHERE ACCOUNT_ID_ = ? AND DEVICE_ID_ = ?`, accountID, id)
	device, err := scanDevice(row)
	if err != nil {
		return nil, err
	}
	return &AccountSession{Device: *device, AccountID: accountID}, nil
}

func (s *Store) FindActiveAccountSessionByToken(token string) (*AccountSession, error) {
	id, secret, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok || uuid.Validate(id) != nil || secret == "" {
		return nil, errors.New("invalid device credential")
	}
	var accountID string
	if err := s.db.QueryRow(`SELECT ACCOUNT_ID_ FROM DEVICE_ WHERE DEVICE_ID_ = ? AND ACCOUNT_ID_ != '' AND STATUS_ = 'ACTIVE'`, id).Scan(&accountID); err != nil {
		return nil, err
	}
	session, err := s.FindAccountSessionByID(accountID, id)
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(session.DeviceTokenBcrypt), []byte(secret)) != nil {
		return nil, errors.New("invalid device credential")
	}
	return session, nil
}

func (s *Store) TouchAccountSession(accountID, id string) error {
	now := time.Now().UTC()
	result, err := s.db.Exec(`UPDATE DEVICE_ SET LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE ACCOUNT_ID_ = ? AND DEVICE_ID_ = ? AND STATUS_ = 'ACTIVE'`, now, now, accountID, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RevokeAccountSession(accountID, id string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE DEVICE_ SET STATUS_ = 'REVOKED', REVOKED_AT_ = ?, UPDATE_AT_ = ? WHERE ACCOUNT_ID_ = ? AND DEVICE_ID_ = ? AND STATUS_ = 'ACTIVE'`, now, now, accountID, id)
	return err
}

func (s *Store) RotateAccountSessionCredential(accountID, id, expectedHash string) (string, error) {
	secret, err := randomAuthSecret()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	result, err := s.db.Exec(`UPDATE DEVICE_ SET DEVICE_TOKEN_BCRYPT_ = ?, LAST_SEEN_AT_ = ?, UPDATE_AT_ = ? WHERE ACCOUNT_ID_ = ? AND DEVICE_ID_ = ? AND STATUS_ = 'ACTIVE' AND DEVICE_TOKEN_BCRYPT_ = ?`, string(hash), now, now, accountID, id, expectedHash)
	if err != nil {
		return "", err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if count != 1 {
		return "", sql.ErrNoRows
	}
	return id + "." + secret, nil
}
