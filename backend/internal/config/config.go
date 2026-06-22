package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

var bcryptPattern = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)

type defaults struct {
	ServerPort           int
	DBPath               string
	Issuer               string
	AdminUsername        string
	AppUsername          string
	AppAccessTTL         string
	AppMaxAccessTTL      string
	AppRotateDeviceToken bool
	TokenAccessTTL       string
	TokenRefreshTTL      string
	TokenRotateRefresh   bool
	CleanupRetention     string
	CleanupCron          string
}

func defaultDBPath() string {
	if serviceDataDir := strings.TrimSpace(os.Getenv("SERVICE_DATA_DIR")); serviceDataDir != "" {
		return filepath.Join(serviceDataDir, "auth.db")
	}
	return "../data/auth.db"
}

var builtInDefaults = defaults{
	ServerPort:           8080,
	DBPath:               "../data/auth.db",
	Issuer:               "http://localhost:8080",
	AdminUsername:        "admin",
	AppUsername:          "app",
	AppAccessTTL:         "PT24H",
	AppMaxAccessTTL:      "P30D",
	AppRotateDeviceToken: true,
	TokenAccessTTL:       "PT24H",
	TokenRefreshTTL:      "P30D",
	TokenRotateRefresh:   true,
	CleanupRetention:     "PT24H",
	CleanupCron:          "0 0 * * * *",
}

type Config struct {
	ServerPort      int
	DBPath          string
	Issuer          string
	FrontendDistDir string

	AdminUsername       string
	AdminPasswordBcrypt string

	AppUsername             string
	AppMasterPasswordBcrypt string
	AppAccessTTL            time.Duration
	AppMaxAccessTTL         time.Duration
	AppRotateDeviceToken    bool

	TokenAccessTTL     time.Duration
	TokenRefreshTTL    time.Duration
	TokenRotateRefresh bool

	CleanupRetention time.Duration
	CleanupCron      string
}

func Load() (*Config, error) {
	_ = godotenv.Load("../.env", ".env")

	port := envInt("SERVER_PORT", builtInDefaults.ServerPort)
	cfg := &Config{
		ServerPort:          port,
		DBPath:              env("AUTH_DB_PATH", defaultDBPath()),
		Issuer:              env("AUTH_ISSUER", builtInDefaults.Issuer),
		FrontendDistDir:     env("FRONTEND_DIST_DIR", ""),
		AdminUsername:       env("AUTH_ADMIN_USERNAME", builtInDefaults.AdminUsername),
		AdminPasswordBcrypt: normalizeQuotedValue(env("AUTH_ADMIN_PASSWORD_BCRYPT", "")),
		AppUsername:         env("AUTH_APP_USERNAME", builtInDefaults.AppUsername),
		AppMasterPasswordBcrypt: normalizeQuotedValue(
			env("AUTH_APP_MASTER_PASSWORD_BCRYPT", ""),
		),
		AppRotateDeviceToken: envBool("AUTH_APP_ROTATE_DEVICE_TOKEN", builtInDefaults.AppRotateDeviceToken),
		TokenRotateRefresh:   envBool("AUTH_TOKEN_ROTATE_REFRESH_TOKEN", builtInDefaults.TokenRotateRefresh),
		CleanupCron:          env("AUTH_CLEANUP_CRON", builtInDefaults.CleanupCron),
	}

	var err error
	cfg.AppAccessTTL, err = parseFlexibleDuration(env("AUTH_APP_ACCESS_TTL", builtInDefaults.AppAccessTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_APP_ACCESS_TTL: %w", err)
	}
	cfg.AppMaxAccessTTL, err = parseFlexibleDuration(env("AUTH_APP_MAX_ACCESS_TTL", builtInDefaults.AppMaxAccessTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_APP_MAX_ACCESS_TTL: %w", err)
	}
	cfg.TokenAccessTTL, err = parseFlexibleDuration(env("AUTH_TOKEN_ACCESS_TTL", builtInDefaults.TokenAccessTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_TOKEN_ACCESS_TTL: %w", err)
	}
	cfg.TokenRefreshTTL, err = parseFlexibleDuration(env("AUTH_TOKEN_REFRESH_TTL", builtInDefaults.TokenRefreshTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_TOKEN_REFRESH_TTL: %w", err)
	}
	cfg.CleanupRetention, err = parseFlexibleDuration(env("AUTH_CLEANUP_RETENTION", builtInDefaults.CleanupRetention))
	if err != nil {
		return nil, fmt.Errorf("invalid AUTH_CLEANUP_RETENTION: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	if strings.TrimSpace(cfg.FrontendDistDir) != "" {
		abs, err := filepath.Abs(cfg.FrontendDistDir)
		if err != nil {
			return nil, fmt.Errorf("resolve FRONTEND_DIST_DIR: %w", err)
		}
		cfg.FrontendDistDir = abs
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	if !bcryptPattern.MatchString(cfg.AdminPasswordBcrypt) {
		return fmt.Errorf("AUTH_ADMIN_PASSWORD_BCRYPT must be a valid bcrypt hash")
	}
	if !bcryptPattern.MatchString(cfg.AppMasterPasswordBcrypt) {
		return fmt.Errorf("AUTH_APP_MASTER_PASSWORD_BCRYPT must be a valid bcrypt hash")
	}
	if cfg.AppMaxAccessTTL <= 0 {
		return fmt.Errorf("AUTH_APP_MAX_ACCESS_TTL must be positive")
	}
	if cfg.AppAccessTTL <= 0 {
		return fmt.Errorf("AUTH_APP_ACCESS_TTL must be positive")
	}
	if cfg.TokenAccessTTL <= 0 || cfg.TokenRefreshTTL <= 0 {
		return fmt.Errorf("token TTL must be positive")
	}
	return nil
}

func env(k, fallback string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	return v
}

func envInt(k string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(k string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func normalizeQuotedValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= 2 {
		first := trimmed[0]
		last := trimmed[len(trimmed)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			return trimmed[1 : len(trimmed)-1]
		}
	}
	return trimmed
}

func parseFlexibleDuration(raw string) (time.Duration, error) {
	v := strings.TrimSpace(strings.ToUpper(raw))
	if v == "" {
		return 0, fmt.Errorf("duration is empty")
	}
	if strings.HasPrefix(v, "P") {
		if strings.HasPrefix(v, "PT") {
			normalized := strings.TrimPrefix(v, "PT")
			normalized = strings.ReplaceAll(normalized, "D", "24H")
			return time.ParseDuration(strings.ToLower(normalized))
		}
		if strings.HasSuffix(v, "D") {
			n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(v, "P"), "D"))
			if err != nil {
				return 0, err
			}
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(strings.ToLower(v)); err == nil {
		return d, nil
	}
	return 0, fmt.Errorf("unsupported duration format: %s", raw)
}
