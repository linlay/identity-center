package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmailFormat      = errors.New("invalid email request")
	ErrEmailUnavailable = errors.New("email unavailable")
	ErrEmailChallenge   = errors.New("invalid email authentication")
	ErrEmailSend        = errors.New("email temporarily unavailable")
)

type EmailRateError struct{ RetryAt int64 }

func (e *EmailRateError) Error() string { return "too many email requests" }

// Deliberately support one ASCII mailbox, not display names or provider alias rules.
var emailPattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$")

func NormalizeEmail(raw string) (string, string, error) {
	email := strings.TrimSpace(raw)
	local, domain, ok := strings.Cut(email, "@")
	if !ok || len(email) > 254 || len(local) > 64 || !emailPattern.MatchString(email) {
		return "", "", ErrEmailFormat
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 {
			return "", "", ErrEmailFormat
		}
	}
	return email, strings.ToLower(email), nil
}
func EmailDigest(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
func GenerateEmailCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

type EmailBinding struct {
	Email              string    `json:"email"`
	BoundAt            time.Time `json:"boundAt"`
	Key, ID, AccountID string    `json:"-"`
}
type EmailChallenge struct {
	SchemaVersion                                                    int       `json:"schemaVersion"`
	ID                                                               string    `json:"challengeId"`
	ExpiresAt                                                        time.Time `json:"expiresAt"`
	ResendAvailableAt                                                time.Time `json:"resendAvailableAt"`
	ServerTime                                                       time.Time `json:"serverTime"`
	Purpose, EmailKey, Email, AccountID, DeviceID, BindingID, Status string    `json:"-"`
}
type EmailLimits struct{ EmailHour, EmailDay, AccountHour, AccountDay, IPHour, IPDay, FailureHour int }
type EmailChallengeInput struct {
	Purpose, Email, AccountID, DeviceID, IP, RequestID, Secret string
	Limits                                                     EmailLimits
	ResponseDelay                                              time.Duration
}

func (s *Store) AccountEmail(accountID string) (*EmailBinding, error) {
	var b EmailBinding
	var at int64
	err := s.db.QueryRow(`SELECT EMAIL_,EMAIL_KEY_,BINDING_ID_,BOUND_AT_,ACCOUNT_ID_ FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=?`, accountID).Scan(&b.Email, &b.Key, &b.ID, &at, &b.AccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.BoundAt = time.UnixMilli(at).UTC()
	return &b, nil
}
func readEmailChallenge(tx *sql.Tx, clause string, args ...any) (*EmailChallenge, string, int, error) {
	var c EmailChallenge
	var hash string
	var fails int
	var at, expiry, resend int64
	err := tx.QueryRow(`SELECT ID_,PURPOSE_,EMAIL_KEY_,EMAIL_,ACCOUNT_ID_,DEVICE_ID_,BINDING_ID_,STATUS_,CODE_HASH_,FAILURES_,CREATED_AT_,EXPIRES_AT_,RESEND_AT_ FROM EMAIL_CHALLENGE_ WHERE `+clause, args...).Scan(&c.ID, &c.Purpose, &c.EmailKey, &c.Email, &c.AccountID, &c.DeviceID, &c.BindingID, &c.Status, &hash, &fails, &at, &expiry, &resend)
	c.SchemaVersion = 1
	c.ExpiresAt = time.UnixMilli(expiry).UTC()
	c.ResendAvailableAt = time.UnixMilli(resend).UTC()
	return &c, hash, fails, err
}

// Acquire the SQLite writer before reading, avoiding deferred read-to-write races.
func emailWriteLock(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT OR IGNORE INTO EMAIL_LIMIT_(KIND_,KEY_,WINDOW_,COUNT_) VALUES('lock','',0,0)`)
	return err
}
func emailCount(tx *sql.Tx, kind, key string, window int64, limit int, retryAt int64) error {
	var n int
	err := tx.QueryRow(`SELECT COUNT_ FROM EMAIL_LIMIT_ WHERE KIND_=? AND KEY_=? AND WINDOW_=?`, kind, key, window).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if n >= limit {
		return &EmailRateError{retryAt}
	}
	return nil
}
func bumpEmailCount(tx *sql.Tx, kind, key string, window int64) error {
	_, err := tx.Exec(`INSERT INTO EMAIL_LIMIT_(KIND_,KEY_,WINDOW_,COUNT_) VALUES(?,?,?,1) ON CONFLICT(KIND_,KEY_,WINDOW_) DO UPDATE SET COUNT_=COUNT_+1`, kind, key, window)
	return err
}
func emailRateScopes(secret, email, account, ip string) [][2]string {
	out := [][2]string{{"ip", EmailDigest(secret, ip)}}
	if email != "" {
		out = append(out, [2]string{"email", EmailDigest(secret, email)})
	}
	if account != "" {
		out = append(out, [2]string{"account", EmailDigest(secret, account)})
	}
	return out
}

// Reserves quota once. The caller sends outside the transaction, only for a new reservation.
func (s *Store) ReserveEmailChallenge(in EmailChallengeInput, now time.Time) (*EmailChallenge, string, bool, error) {
	if uuid.Validate(in.RequestID) != nil || len(in.Secret) < 32 || (in.Purpose != "login" && in.Purpose != "bind" && in.Purpose != "unbind") {
		return nil, "", false, ErrEmailFormat
	}
	email, key, err := NormalizeEmail(in.Email)
	if in.Purpose == "unbind" {
		email = ""
		key = ""
		err = nil
	}
	if err != nil {
		return nil, "", false, err
	}
	code, err := GenerateEmailCode()
	if err != nil {
		return nil, "", false, err
	}
	var result *EmailChallenge
	var fresh bool
	err = s.WithTx(func(tx *sql.Tx) error {
		if err := emailWriteLock(tx); err != nil {
			return err
		}
		bindingID, accountID, deviceID := "", in.AccountID, in.DeviceID
		if in.Purpose != "login" {
			var valid int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM DEVICE_ d JOIN APP_USER_ u ON u.USER_ID_=d.ACCOUNT_ID_ WHERE d.ACCOUNT_ID_=? AND d.DEVICE_ID_=? AND d.STATUS_='ACTIVE' AND u.STATUS_='ACTIVE'`, accountID, deviceID).Scan(&valid); err != nil {
				return err
			}
			if valid != 1 {
				return ErrEmailChallenge
			}
		}
		if in.Purpose == "login" {
			accountID = ""
			deviceID = ""
			err := tx.QueryRow(`SELECT e.ACCOUNT_ID_,e.BINDING_ID_,e.EMAIL_ FROM ACCOUNT_EMAIL_ e JOIN APP_USER_ u ON u.USER_ID_=e.ACCOUNT_ID_ WHERE e.EMAIL_KEY_=? AND u.STATUS_='ACTIVE'`, key).Scan(&accountID, &bindingID, &email)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if errors.Is(err, sql.ErrNoRows) {
				email = ""
			}
		} else if in.Purpose == "unbind" {
			err := tx.QueryRow(`SELECT EMAIL_,EMAIL_KEY_,BINDING_ID_ FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=?`, accountID).Scan(&email, &key, &bindingID)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEmailUnavailable
			}
			if err != nil {
				return err
			}
		}
		// Public quota is keyed by mailbox/IP, independent of whether a binding exists.
		quotaAccount := accountID
		if in.Purpose == "login" {
			quotaAccount = ""
		}
		requestKey := EmailDigest(in.Secret, in.Purpose+"\x00"+key+"\x00"+in.AccountID+"\x00"+deviceID+"\x00"+in.RequestID)
		old, _, _, err := readEmailChallenge(tx, "REQUEST_KEY_=?", requestKey)
		if err == nil {
			if old.Status == "active" || in.Purpose == "login" {
				old.ServerTime = now
				result = old
				return nil
			}
			return ErrEmailSend
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if in.Purpose == "bind" {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=? OR EMAIL_KEY_=?`, accountID, key).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrEmailUnavailable
			}
		}
		var cooldown int64
		err = tx.QueryRow(`SELECT COUNT_ FROM EMAIL_LIMIT_ WHERE KIND_='cooldown' AND KEY_=? AND WINDOW_=0`, EmailDigest(in.Secret, key)).Scan(&cooldown)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if cooldown > now.UnixMilli() {
			return &EmailRateError{cooldown}
		}
		scopes := emailRateScopes(in.Secret, key, quotaAccount, in.IP)
		for _, scope := range scopes {
			hourLimit, dayLimit := in.Limits.EmailHour, in.Limits.EmailDay
			if scope[0] == "ip" {
				hourLimit, dayLimit = in.Limits.IPHour, in.Limits.IPDay
			}
			if scope[0] == "account" {
				hourLimit, dayLimit = in.Limits.AccountHour, in.Limits.AccountDay
			}
			hour, day := now.UnixMilli()/3600000, now.UnixMilli()/86400000
			if err := emailCount(tx, "send-"+scope[0]+"-hour", scope[1], hour, hourLimit, (hour+1)*3600000); err != nil {
				return err
			}
			if err := emailCount(tx, "send-"+scope[0]+"-day", scope[1], day, dayLimit, (day+1)*86400000); err != nil {
				return err
			}
			if err := emailCount(tx, "fail-"+scope[0], scope[1], hour, in.Limits.FailureHour, (hour+1)*3600000); err != nil {
				return err
			}
			if err := bumpEmailCount(tx, "send-"+scope[0]+"-hour", scope[1], hour); err != nil {
				return err
			}
			if err := bumpEmailCount(tx, "send-"+scope[0]+"-day", scope[1], day); err != nil {
				return err
			}
		}
		readyAt := now
		if in.Purpose == "login" {
			readyAt = now.Add(in.ResponseDelay)
		}
		// Reserve the cooldown even on failed/unknown delivery; never blindly retry a requestId.
		_, err = tx.Exec(`INSERT INTO EMAIL_LIMIT_(KIND_,KEY_,WINDOW_,COUNT_) VALUES('cooldown',?,0,?) ON CONFLICT(KIND_,KEY_,WINDOW_) DO UPDATE SET COUNT_=excluded.COUNT_`, EmailDigest(in.Secret, key), readyAt.Add(time.Minute).UnixMilli())
		if err != nil {
			return err
		}
		id := uuid.NewString()
		expiry, resend := readyAt.Add(5*time.Minute), readyAt.Add(time.Minute)
		_, err = tx.Exec(`INSERT INTO EMAIL_CHALLENGE_(ID_,REQUEST_KEY_,PURPOSE_,EMAIL_KEY_,EMAIL_,ACCOUNT_ID_,DEVICE_ID_,BINDING_ID_,CODE_HASH_,STATUS_,CREATED_AT_,EXPIRES_AT_,RESEND_AT_) VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?)`, id, requestKey, in.Purpose, key, email, accountID, deviceID, bindingID, EmailDigest(in.Secret, id+"\x00"+code), now.UnixMilli(), expiry.UnixMilli(), resend.UnixMilli())
		if err != nil {
			return err
		}
		result = &EmailChallenge{SchemaVersion: 1, ID: id, Purpose: in.Purpose, EmailKey: key, Email: email, AccountID: accountID, DeviceID: deviceID, BindingID: bindingID, ExpiresAt: expiry, ResendAvailableAt: resend, ServerTime: now}
		fresh = true
		return nil
	})
	return result, code, fresh, err
}
func (s *Store) FinishEmailSend(c *EmailChallenge, accepted bool, secret string, now time.Time) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if err := emailWriteLock(tx); err != nil {
			return err
		}
		expiry, resend := now.Add(5*time.Minute), now.Add(time.Minute)
		c.ExpiresAt = expiry
		c.ResendAvailableAt = resend
		c.ServerTime = now
		if !accepted {
			if _, err := tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET STATUS_='failed',EXPIRES_AT_=?,RESEND_AT_=? WHERE ID_=? AND STATUS_='pending'`, expiry.UnixMilli(), resend.UnixMilli(), c.ID); err != nil {
				return err
			}
			_, err := tx.Exec(`UPDATE EMAIL_LIMIT_ SET COUNT_=? WHERE KIND_='cooldown' AND KEY_=? AND WINDOW_=0`, resend.UnixMilli(), EmailDigest(secret, c.EmailKey))
			return err
		}
		// Binding identity is checked again at consumption; fake login challenges never have one.
		_, err := tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET STATUS_='superseded' WHERE PURPOSE_=? AND EMAIL_KEY_=? AND ACCOUNT_ID_=? AND STATUS_='active'`, c.Purpose, c.EmailKey, c.AccountID)
		if err != nil {
			return err
		}
		r, err := tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET STATUS_='active',EXPIRES_AT_=?,RESEND_AT_=? WHERE ID_=? AND STATUS_='pending'`, expiry.UnixMilli(), resend.UnixMilli(), c.ID)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrEmailChallenge
		}
		_, err = tx.Exec(`UPDATE EMAIL_LIMIT_ SET COUNT_=? WHERE KIND_='cooldown' AND KEY_=? AND WINDOW_=0`, resend.UnixMilli(), EmailDigest(secret, c.EmailKey))
		c.Status = "active"
		return err
	})
}

type EmailConsumeInput struct {
	ID, Code, Purpose, AccountID, DeviceID, IP, Secret, DeviceName string
	FailureHour                                                    int
}
type EmailConsumeResult struct {
	User    *User
	Session *CreateAccountSessionResult
	Binding *EmailBinding
}

func (s *Store) ConsumeEmailChallenge(in EmailConsumeInput, now time.Time) (*EmailConsumeResult, error) {
	if uuid.Validate(in.ID) != nil || len(in.Code) != 6 || len(in.Secret) < 32 {
		return nil, ErrEmailChallenge
	}
	for _, r := range in.Code {
		if r < '0' || r > '9' {
			return nil, ErrEmailChallenge
		}
	}
	var prepared *CreateAccountSessionResult
	if in.Purpose == "login" {
		var hash, status, purpose, accountID string
		var expiry int64
		var failures int
		err := s.db.QueryRow(`SELECT CODE_HASH_,STATUS_,PURPOSE_,ACCOUNT_ID_,EXPIRES_AT_,FAILURES_ FROM EMAIL_CHALLENGE_ WHERE ID_=?`, in.ID).Scan(&hash, &status, &purpose, &accountID, &expiry, &failures)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		// Expensive device credential hashing is only needed for a matching challenge.
		if err == nil && status == "active" && purpose == "login" && accountID != "" && failures < 5 && now.UnixMilli() < expiry && subtle.ConstantTimeCompare([]byte(hash), []byte(EmailDigest(in.Secret, in.ID+"\x00"+in.Code))) == 1 {
			p, err := prepareAccountSession(accountID, in.DeviceName)
			if err != nil {
				return nil, err
			}
			prepared = &p
		}
	}
	var result EmailConsumeResult
	var rejected error
	err := s.WithTx(func(tx *sql.Tx) error {
		if err := emailWriteLock(tx); err != nil {
			return err
		}
		c, hash, failures, err := readEmailChallenge(tx, "ID_=?", in.ID)
		email, account := "", in.AccountID
		if err == nil {
			email = c.EmailKey
			if in.Purpose == "login" {
				account = c.AccountID
			}
		}
		// Count failed verification, including wrong IDs, against caller IP/account too.
		hour := now.UnixMilli() / 3600000
		scopes := emailRateScopes(in.Secret, email, account, in.IP)
		for _, scope := range scopes {
			if err := emailCount(tx, "fail-"+scope[0], scope[1], hour, in.FailureHour, (hour+1)*3600000); err != nil {
				rejected = err
				return nil
			}
		}
		valid := err == nil && (in.Purpose != "login" || prepared != nil) && c.Purpose == in.Purpose && c.Status == "active" && failures < 5 && now.Before(c.ExpiresAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if valid && in.Purpose != "login" {
			valid = c.AccountID == in.AccountID && c.DeviceID == in.DeviceID
		}
		if valid {
			valid = subtle.ConstantTimeCompare([]byte(hash), []byte(EmailDigest(in.Secret, c.ID+"\x00"+in.Code))) == 1
		}
		if valid {
			row := tx.QueryRow(`SELECT USER_ID_,USERNAME_,PASSWORD_BCRYPT_,DISPLAY_NAME_,STATUS_,CREATE_AT_,UPDATE_AT_ FROM APP_USER_ WHERE USER_ID_=? AND STATUS_='ACTIVE'`, c.AccountID)
			user, e := scanUser(row)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			valid = e == nil
			result.User = user
		}
		if valid && in.Purpose != "login" {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM DEVICE_ WHERE ACCOUNT_ID_=? AND DEVICE_ID_=? AND STATUS_='ACTIVE'`, in.AccountID, in.DeviceID).Scan(&n); err != nil {
				return err
			}
			valid = n == 1
		}
		if valid && (in.Purpose == "login" || in.Purpose == "unbind") {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=? AND EMAIL_KEY_=? AND BINDING_ID_=?`, c.AccountID, c.EmailKey, c.BindingID).Scan(&n); err != nil {
				return err
			}
			valid = n == 1
		}
		if !valid {
			for _, scope := range scopes {
				if err := bumpEmailCount(tx, "fail-"+scope[0], scope[1], hour); err != nil {
					return err
				}
			}
			if c != nil && c.ID != "" {
				if _, err := tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET FAILURES_=FAILURES_+1 WHERE ID_=? AND STATUS_='active'`, in.ID); err != nil {
					return err
				}
			}
			rejected = ErrEmailChallenge
			return nil // commit the failed attempt, not a rollback
		}
		switch in.Purpose {
		case "login":
			prepared.Session.AccountID = c.AccountID
			if err := insertAccountSession(tx, prepared.Session); err != nil {
				return err
			}
			result.Session = prepared
		case "bind":
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=? OR EMAIL_KEY_=?`, c.AccountID, c.EmailKey).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return ErrEmailUnavailable
			}
			id := uuid.NewString()
			if _, err := tx.Exec(`INSERT INTO ACCOUNT_EMAIL_(ACCOUNT_ID_,EMAIL_KEY_,EMAIL_,BINDING_ID_,BOUND_AT_) VALUES(?,?,?,?,?)`, c.AccountID, c.EmailKey, c.Email, id, now.UnixMilli()); err != nil {
				return err
			}
			if err := recordEmailAudit(tx, c.AccountID, in.DeviceID, "bind", EmailDigest(in.Secret, c.EmailKey), "", now); err != nil {
				return err
			}
			result.Binding = &EmailBinding{Email: c.Email, BoundAt: now, ID: id, Key: c.EmailKey, AccountID: c.AccountID}
		case "unbind":
			if err := unbindAccountEmail(tx, c.AccountID, in.DeviceID, EmailDigest(in.Secret, c.EmailKey), "", now); err != nil {
				return err
			}
		default:
			return ErrEmailChallenge
		}
		_, err = tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET STATUS_='consumed' WHERE ID_=?`, c.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if rejected != nil {
		return nil, rejected
	}
	return &result, nil
}
func recordEmailAudit(tx *sql.Tx, account, actor, action, hash, reason string, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO EMAIL_AUDIT_(ID_,ACCOUNT_ID_,ACTOR_,ACTION_,EMAIL_KEY_HASH_,REASON_,CREATED_AT_) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), account, actor, action, hash, reason, now.UnixMilli())
	return err
}
func unbindAccountEmail(tx *sql.Tx, account, actor, hash, reason string, now time.Time) error {
	if _, err := tx.Exec(`UPDATE EMAIL_CHALLENGE_ SET STATUS_='invalidated' WHERE ACCOUNT_ID_=? AND STATUS_ IN ('active','pending')`, account); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=?`, account); err != nil {
		return err
	}
	return recordEmailAudit(tx, account, actor, "unbind", hash, reason, now)
}
func (s *Store) AdminUnbindAccountEmail(account, actor, reason, secret string, now time.Time) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 500 {
		return ErrEmailFormat
	}
	return s.WithTx(func(tx *sql.Tx) error {
		if err := emailWriteLock(tx); err != nil {
			return err
		}
		var key string
		err := tx.QueryRow(`SELECT EMAIL_KEY_ FROM ACCOUNT_EMAIL_ WHERE ACCOUNT_ID_=?`, account).Scan(&key)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmailUnavailable
		}
		if err != nil {
			return err
		}
		return unbindAccountEmail(tx, account, actor, EmailDigest(secret, key), reason, now)
	})
}
func (s *Store) CleanupEmailAuth(now time.Time) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM EMAIL_CHALLENGE_ WHERE EXPIRES_AT_<?`, now.Add(-24*time.Hour).UnixMilli()); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM EMAIL_LIMIT_ WHERE (KIND_ LIKE '%-hour' OR KIND_ LIKE 'fail-%') AND WINDOW_<?`, now.UnixMilli()/3600000-48); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM EMAIL_LIMIT_ WHERE KIND_ LIKE '%-day' AND WINDOW_<?`, now.UnixMilli()/86400000-2); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM EMAIL_LIMIT_ WHERE KIND_='cooldown' AND COUNT_<?`, now.Add(-24*time.Hour).UnixMilli())
		return err
	})
}
