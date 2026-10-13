package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrLoginChallengeNotFound  = errors.New("login challenge not found")
	ErrLoginChallengeExpired   = errors.New("login challenge expired")
	ErrLoginChallengeConsumed  = errors.New("login challenge already consumed")
	ErrLoginChallengeNotReady  = errors.New("login challenge not confirmed")
	ErrLoginChallengeToken     = errors.New("invalid login challenge token")
	ErrLoginChallengeConfirmer = errors.New("confirming session is inactive")
)

type LoginChallenge struct {
	ChallengeID       string
	ClaimTokenSHA256  string
	TargetDeviceName  string
	Status            string
	AccountID         string
	ConfirmerDeviceID string
	ExpiresAt         time.Time
	ConfirmedAt       *time.Time
	ClaimedAt         *time.Time
	CreateAt          time.Time
	UpdateAt          time.Time
}

type CreateLoginChallengeResult struct {
	Challenge  LoginChallenge
	ClaimToken string
}

func (s *Store) CreateLoginChallenge(deviceName string, now time.Time, ttl time.Duration) (CreateLoginChallengeResult, error) {
	deviceName = strings.TrimSpace(deviceName)
	if !validSessionName(deviceName) || ttl <= 0 {
		return CreateLoginChallengeResult{}, errors.New("invalid login challenge input")
	}
	claimToken, err := randomAuthSecret()
	if err != nil {
		return CreateLoginChallengeResult{}, err
	}
	now = now.UTC()
	challenge := LoginChallenge{
		ChallengeID: uuid.NewString(), ClaimTokenSHA256: challengeTokenSHA256(claimToken),
		TargetDeviceName: deviceName, Status: "PENDING",
		ExpiresAt: now.Add(ttl), CreateAt: now, UpdateAt: now,
	}
	_, err = s.db.Exec(`INSERT INTO LOGIN_CHALLENGE_(CHALLENGE_ID_, CLAIM_TOKEN_SHA256_, TARGET_DEVICE_NAME_, STATUS_, ACCOUNT_ID_, CONFIRMER_DEVICE_ID_, EXPIRES_AT_, CONFIRMED_AT_, CLAIMED_AT_, CREATE_AT_, UPDATE_AT_) VALUES(?, ?, ?, 'PENDING', '', '', ?, NULL, NULL, ?, ?)`,
		challenge.ChallengeID, challenge.ClaimTokenSHA256, challenge.TargetDeviceName, challenge.ExpiresAt, now, now)
	if err != nil {
		return CreateLoginChallengeResult{}, err
	}
	return CreateLoginChallengeResult{Challenge: challenge, ClaimToken: claimToken}, nil
}

func (s *Store) FindLoginChallenge(challengeID string, now time.Time) (*LoginChallenge, error) {
	challenge, err := scanLoginChallenge(s.db.QueryRow(`SELECT CHALLENGE_ID_, CLAIM_TOKEN_SHA256_, TARGET_DEVICE_NAME_, STATUS_, ACCOUNT_ID_, CONFIRMER_DEVICE_ID_, EXPIRES_AT_, CONFIRMED_AT_, CLAIMED_AT_, CREATE_AT_, UPDATE_AT_ FROM LOGIN_CHALLENGE_ WHERE CHALLENGE_ID_ = ?`, strings.TrimSpace(challengeID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLoginChallengeNotFound
	}
	if err != nil {
		return nil, err
	}
	if !challenge.ExpiresAt.After(now.UTC()) {
		return nil, ErrLoginChallengeExpired
	}
	if challenge.Status == "CLAIMED" {
		return nil, ErrLoginChallengeConsumed
	}
	return challenge, nil
}

func (s *Store) ConfirmLoginChallenge(challengeID, accountID, confirmerDeviceID string, now time.Time) (*LoginChallenge, error) {
	now = now.UTC()
	result, err := s.db.Exec(`UPDATE LOGIN_CHALLENGE_ SET STATUS_ = 'CONFIRMED', ACCOUNT_ID_ = ?, CONFIRMER_DEVICE_ID_ = ?, CONFIRMED_AT_ = ?, UPDATE_AT_ = ? WHERE CHALLENGE_ID_ = ? AND STATUS_ = 'PENDING' AND EXPIRES_AT_ > ?`,
		accountID, confirmerDeviceID, now, now, strings.TrimSpace(challengeID), now)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, loginChallengeTransitionError(s.db, challengeID, now)
	}
	return s.FindLoginChallenge(challengeID, now)
}

func (s *Store) ClaimLoginChallenge(challengeID, claimToken string, now time.Time) (*LoginChallenge, error) {
	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Write first: SQLite writers serialize without a deferred read-lock upgrade.
	// The same atomic condition checks expiry, one-time state, credential, account and confirmer.
	result, err := tx.Exec(`UPDATE LOGIN_CHALLENGE_ SET STATUS_ = 'CLAIMED', CLAIMED_AT_ = ?, UPDATE_AT_ = ? WHERE CHALLENGE_ID_ = ? AND STATUS_ = 'CONFIRMED' AND EXPIRES_AT_ > ? AND CLAIM_TOKEN_SHA256_ = ? AND EXISTS (SELECT 1 FROM DEVICE_ d JOIN APP_USER_ u ON u.USER_ID_ = d.ACCOUNT_ID_ WHERE d.ACCOUNT_ID_ = LOGIN_CHALLENGE_.ACCOUNT_ID_ AND d.DEVICE_ID_ = LOGIN_CHALLENGE_.CONFIRMER_DEVICE_ID_ AND d.STATUS_ = 'ACTIVE' AND u.STATUS_ = 'ACTIVE')`, now, now, strings.TrimSpace(challengeID), now, challengeTokenSHA256(strings.TrimSpace(claimToken)))
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		challenge, err := s.FindLoginChallenge(challengeID, now)
		if err != nil {
			return nil, err
		}
		if challenge.Status != "CONFIRMED" {
			return nil, ErrLoginChallengeNotReady
		}
		if subtle.ConstantTimeCompare([]byte(challenge.ClaimTokenSHA256), []byte(challengeTokenSHA256(strings.TrimSpace(claimToken)))) != 1 {
			return nil, ErrLoginChallengeToken
		}
		return nil, ErrLoginChallengeConfirmer
	}
	challenge, err := scanLoginChallenge(tx.QueryRow(`SELECT CHALLENGE_ID_, CLAIM_TOKEN_SHA256_, TARGET_DEVICE_NAME_, STATUS_, ACCOUNT_ID_, CONFIRMER_DEVICE_ID_, EXPIRES_AT_, CONFIRMED_AT_, CLAIMED_AT_, CREATE_AT_, UPDATE_AT_ FROM LOGIN_CHALLENGE_ WHERE CHALLENGE_ID_ = ?`, strings.TrimSpace(challengeID)))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return challenge, nil
}

func loginChallengeTransitionError(database *sql.DB, challengeID string, now time.Time) error {
	challenge, err := scanLoginChallenge(database.QueryRow(`SELECT CHALLENGE_ID_, CLAIM_TOKEN_SHA256_, TARGET_DEVICE_NAME_, STATUS_, ACCOUNT_ID_, CONFIRMER_DEVICE_ID_, EXPIRES_AT_, CONFIRMED_AT_, CLAIMED_AT_, CREATE_AT_, UPDATE_AT_ FROM LOGIN_CHALLENGE_ WHERE CHALLENGE_ID_ = ?`, strings.TrimSpace(challengeID)))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLoginChallengeNotFound
	}
	if err != nil {
		return err
	}
	if !challenge.ExpiresAt.After(now) {
		return ErrLoginChallengeExpired
	}
	return ErrLoginChallengeConsumed
}

func scanLoginChallenge(scanner interface{ Scan(...any) error }) (*LoginChallenge, error) {
	var challenge LoginChallenge
	var confirmedAt, claimedAt sql.NullTime
	if err := scanner.Scan(
		&challenge.ChallengeID, &challenge.ClaimTokenSHA256, &challenge.TargetDeviceName,
		&challenge.Status, &challenge.AccountID, &challenge.ConfirmerDeviceID,
		&challenge.ExpiresAt, &confirmedAt, &claimedAt, &challenge.CreateAt, &challenge.UpdateAt,
	); err != nil {
		return nil, err
	}
	challenge.ExpiresAt = challenge.ExpiresAt.UTC()
	if confirmedAt.Valid {
		value := confirmedAt.Time.UTC()
		challenge.ConfirmedAt = &value
	}
	if claimedAt.Valid {
		value := claimedAt.Time.UTC()
		challenge.ClaimedAt = &value
	}
	return &challenge, nil
}

func (s *Store) DeleteExpiredLoginChallengesOlderThan(retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	result, err := s.db.Exec(`DELETE FROM LOGIN_CHALLENGE_ WHERE STATUS_ IN ('PENDING', 'CONFIRMED', 'CLAIMED') AND EXPIRES_AT_ < ?`, time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func challengeTokenSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
