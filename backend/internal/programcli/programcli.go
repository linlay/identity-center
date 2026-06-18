package programcli

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	"identity-center/backend/internal/db"
	"identity-center/backend/internal/security"
	"identity-center/backend/internal/store"
)

const placeholderDeviceTokenBcrypt = "$2a$10$7J8GmW8J0tR9o5Z8L4m5Uuu6fQW4j6mJjM7qY0Q8n2rM5b3y1fVwK"

type options struct {
	dbPath     string
	outDir     string
	publicOut  string
	mode       string
	keyID      string
	issuer     string
	username   string
	deviceID   string
	deviceName string
	ttlSeconds int64
}

func Run(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "setup-public-key":
		return true, runSetupPublicKey(args[1:], stdout, stderr)
	case "issue-bridge-access-token":
		return true, runIssueBridgeAccessToken(args[1:], stdout, stderr, false)
	case "issue-bridge-runner-token":
		return true, runIssueBridgeAccessToken(args[1:], stdout, stderr, true)
	default:
		return false, nil
	}
}

func runSetupPublicKey(args []string, stdout, stderr io.Writer) error {
	opts := defaultOptions()
	fs := newFlagSet("setup-public-key", stderr)
	bindString(fs, &opts.mode, "mode", "Mode", opts.mode, "bootstrap or rotate")
	bindString(fs, &opts.dbPath, "db", "Db", opts.dbPath, "SQLite database path")
	bindString(fs, &opts.outDir, "out", "Out", opts.outDir, "key output directory")
	bindString(fs, &opts.publicOut, "public-out", "PublicOut", opts.publicOut, "public key output path")
	bindString(fs, &opts.keyID, "key-id", "KeyId", opts.keyID, "JWK key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.mode = strings.ToLower(strings.TrimSpace(opts.mode))
	if opts.mode != "bootstrap" && opts.mode != "rotate" {
		return fmt.Errorf("invalid mode: %s (must be bootstrap or rotate)", opts.mode)
	}
	if strings.TrimSpace(opts.publicOut) == "" {
		opts.publicOut = filepath.Join(opts.outDir, "publicKey.pem")
	}
	conn, keys, err := openKeys(opts.dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	existed, err := hasStoredKey(conn)
	if err != nil {
		return err
	}
	var keyID string
	if opts.mode == "rotate" {
		key, err := keys.Rotate(opts.keyID)
		if err != nil {
			return err
		}
		keyID = key.KeyID
	} else {
		key, err := keys.LoadOrCreateWithKeyID(opts.keyID)
		if err != nil {
			return err
		}
		keyID = key.KeyID
	}
	publicPEM, privatePEM, err := keys.ExportKeyPairPEM()
	if err != nil {
		return err
	}
	if err := writeKeyFiles(opts.outDir, opts.publicOut, publicPEM, privatePEM); err != nil {
		return err
	}
	action := "exported existing"
	if opts.mode == "rotate" || !existed {
		action = "generated and stored new"
	}
	fmt.Fprintf(stdout, "[setup-public-key] %s key pair (kid=%s)\n", action, keyID)
	return nil
}

func runIssueBridgeAccessToken(args []string, stdout, stderr io.Writer, runner bool) error {
	opts := defaultOptions()
	if runner {
		opts.ttlSeconds = 315360000
	}
	fs := newFlagSet(commandName(runner), stderr)
	bindString(fs, &opts.dbPath, "db", "Db", opts.dbPath, "SQLite database path")
	bindString(fs, &opts.issuer, "issuer", "Issuer", opts.issuer, "JWT issuer")
	bindString(fs, &opts.username, "username", "Username", opts.username, "JWT subject")
	bindString(fs, &opts.deviceName, "device-name", "DeviceName", opts.deviceName, "device name")
	bindString(fs, &opts.deviceID, "device-id", "DeviceId", opts.deviceID, "desktop installation device id")
	if runner {
		bindInt64(fs, &opts.ttlSeconds, "ttl-seconds", "TtlSeconds", opts.ttlSeconds, "token TTL in seconds")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runner && opts.ttlSeconds <= 0 {
		return fmt.Errorf("ttl-seconds must be a positive integer")
	}
	if !runner {
		opts.ttlSeconds = 31536000
	}
	conn, keys, err := openKeys(opts.dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	key, err := keys.LoadOrCreate()
	if err != nil {
		return err
	}
	st := store.New(conn)
	device, err := ensureBridgeDevice(st, opts)
	if err != nil {
		return err
	}
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Duration(opts.ttlSeconds) * time.Second)
	token, err := security.SignJWT(key, map[string]any{
		"iss":       opts.issuer,
		"sub":       opts.username,
		"iat":       issuedAt.Unix(),
		"exp":       expiresAt.Unix(),
		"scope":     "app",
		"device_id": device.DeviceID,
	})
	if err != nil {
		return err
	}
	username := opts.username
	deviceID := device.DeviceID
	deviceName := device.DeviceName
	if err := st.RecordTokenAudit("APP_ACCESS", token, &username, &deviceID, &deviceName, nil, nil, issuedAt, &expiresAt); err != nil {
		return err
	}
	if runner {
		fmt.Fprintf(stdout, "RUNNER_BEARER_TOKEN=%s\n", token)
		fmt.Fprintf(stdout, "RUNNER_BEARER_EXPIRES_AT=%d\n", expiresAt.Unix())
		return nil
	}
	fmt.Fprintln(stdout, token)
	return nil
}

func ensureBridgeDevice(st *store.Store, opts options) (*store.Device, error) {
	deviceID := strings.TrimSpace(opts.deviceID)
	if deviceID == "" {
		return st.EnsureActiveDeviceWithHash(opts.deviceName, placeholderDeviceTokenBcrypt)
	}
	if _, err := uuid.Parse(deviceID); err != nil {
		return nil, fmt.Errorf("invalid device-id: %s", deviceID)
	}
	return st.EnsureActiveDeviceWithID(deviceID, opts.deviceName, placeholderDeviceTokenBcrypt)
}

func openKeys(dbPath string) (*sql.DB, *security.KeyManager, error) {
	conn, err := db.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	if err := db.InitEmbeddedSchema(conn); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, security.NewKeyManager(conn), nil
}

func writeKeyFiles(outDir, publicOut, publicPEM, privatePEM string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(publicOut), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "jwk-public.pem"), []byte(publicPEM+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "jwk-private.pem"), []byte(privatePEM+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(publicOut, []byte(publicPEM+"\n"), 0o644)
}

func hasStoredKey(conn *sql.DB) (bool, error) {
	row := conn.QueryRow(`SELECT COUNT(*) FROM JWK_KEY_`)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func defaultOptions() options {
	root := programRoot()
	_ = godotenv.Load(filepath.Join(root, ".env"), ".env")
	outDir := env("KEY_OUTPUT_DIR", filepath.Join(root, "data", "keys"))
	return options{
		dbPath:     env("AUTH_DB_PATH", filepath.Join(root, "data", "auth.db")),
		outDir:     outDir,
		publicOut:  "",
		mode:       "bootstrap",
		keyID:      env("JWK_KEY_ID", ""),
		issuer:     env("AUTH_ISSUER", "http://localhost:8080"),
		username:   env("AUTH_APP_USERNAME", "app"),
		deviceID:   env("DESKTOP_DEVICE_ID", ""),
		deviceName: "WeChat Bridge",
		ttlSeconds: 31536000,
	}
}

func programRoot() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		if filepath.Base(dir) == "backend" {
			return filepath.Dir(dir)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}

func env(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func bindString(fs *flag.FlagSet, target *string, lower, upper, value, usage string) {
	fs.StringVar(target, lower, value, usage)
	fs.StringVar(target, upper, value, usage)
}

func bindInt64(fs *flag.FlagSet, target *int64, lower, upper string, value int64, usage string) {
	fs.Int64Var(target, lower, value, usage)
	fs.Int64Var(target, upper, value, usage)
}

func commandName(runner bool) string {
	if runner {
		return "issue-bridge-runner-token"
	}
	return "issue-bridge-access-token"
}
