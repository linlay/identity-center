package config

import (
	"os"
	"testing"
	"time"
)

const documentedDevBcrypt = "$2a$10$R9SBw8NUY53nl9mg4L206eM0gFmQFqxSIg5ieLKILAiNbbc2ZSVbu"

func chdirTemp(t *testing.T, dir string) {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to temp dir: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}

func TestLoadUsesBuiltInDefaults(t *testing.T) {
	tempDir := t.TempDir()
	chdirTemp(t, tempDir)
	t.Setenv("SERVER_PORT", "")
	t.Setenv("BACKEND_PORT", "")
	t.Setenv("AUTH_DB_PATH", "")
	t.Setenv("AUTH_ISSUER", "")
	t.Setenv("AUTH_ADMIN_USERNAME", "")
	t.Setenv("AUTH_APP_USERNAME", "")
	t.Setenv("AUTH_APP_ACCESS_TTL", "")
	t.Setenv("AUTH_APP_MAX_ACCESS_TTL", "")
	t.Setenv("AUTH_APP_ROTATE_DEVICE_TOKEN", "")
	t.Setenv("AUTH_TOKEN_ACCESS_TTL", "")
	t.Setenv("AUTH_TOKEN_REFRESH_TTL", "")
	t.Setenv("AUTH_TOKEN_ROTATE_REFRESH_TOKEN", "")
	t.Setenv("AUTH_CLEANUP_RETENTION", "")
	t.Setenv("AUTH_CLEANUP_CRON", "")
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ServerPort != builtInDefaults.ServerPort {
		t.Fatalf("unexpected server port: %d", cfg.ServerPort)
	}
	if cfg.DBPath != builtInDefaults.DBPath || cfg.Issuer != builtInDefaults.Issuer {
		t.Fatalf("unexpected defaults: db=%s issuer=%s", cfg.DBPath, cfg.Issuer)
	}
	if cfg.AdminUsername != builtInDefaults.AdminUsername || cfg.AppUsername != builtInDefaults.AppUsername {
		t.Fatalf("unexpected usernames: admin=%s app=%s", cfg.AdminUsername, cfg.AppUsername)
	}
	if cfg.AppAccessTTL != 24*time.Hour || cfg.TokenAccessTTL != 24*time.Hour {
		t.Fatalf("unexpected access TTLs: app=%s token=%s", cfg.AppAccessTTL, cfg.TokenAccessTTL)
	}
	if cfg.AppMaxAccessTTL != 30*24*time.Hour || cfg.TokenRefreshTTL != 30*24*time.Hour {
		t.Fatalf("unexpected max/refresh TTLs: appMax=%s tokenRefresh=%s", cfg.AppMaxAccessTTL, cfg.TokenRefreshTTL)
	}
	if !cfg.AppRotateDeviceToken || !cfg.TokenRotateRefresh {
		t.Fatalf("expected rotate flags true: app=%v token=%v", cfg.AppRotateDeviceToken, cfg.TokenRotateRefresh)
	}
	if cfg.CleanupRetention != 24*time.Hour || cfg.CleanupCron != builtInDefaults.CleanupCron {
		t.Fatalf("unexpected cleanup defaults: retention=%s cron=%s", cfg.CleanupRetention, cfg.CleanupCron)
	}
	if cfg.FrontendDistDir != "" {
		t.Fatalf("expected empty frontend dist dir by default, got: %s", cfg.FrontendDistDir)
	}
}

func TestLoadEnvOverridesBuiltInDefaults(t *testing.T) {
	tempDir := t.TempDir()
	chdirTemp(t, tempDir)
	t.Setenv("SERVER_PORT", "28080")
	t.Setenv("BACKEND_PORT", "")
	t.Setenv("AUTH_DB_PATH", "/tmp/auth.db")
	t.Setenv("AUTH_ISSUER", "http://env.example:28080")
	t.Setenv("AUTH_ADMIN_USERNAME", "env-admin")
	t.Setenv("AUTH_APP_USERNAME", "env-app")
	t.Setenv("AUTH_APP_ACCESS_TTL", "PT5M")
	t.Setenv("AUTH_APP_MAX_ACCESS_TTL", "P2D")
	t.Setenv("AUTH_APP_ROTATE_DEVICE_TOKEN", "false")
	t.Setenv("AUTH_TOKEN_ACCESS_TTL", "PT8M")
	t.Setenv("AUTH_TOKEN_REFRESH_TTL", "P5D")
	t.Setenv("AUTH_TOKEN_ROTATE_REFRESH_TOKEN", "false")
	t.Setenv("AUTH_CLEANUP_RETENTION", "PT6H")
	t.Setenv("AUTH_CLEANUP_CRON", "0 */10 * * * *")
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ServerPort != 28080 || cfg.DBPath != "/tmp/auth.db" || cfg.Issuer != "http://env.example:28080" {
		t.Fatalf("env overrides not applied: port=%d db=%s issuer=%s", cfg.ServerPort, cfg.DBPath, cfg.Issuer)
	}
	if cfg.AdminUsername != "env-admin" || cfg.AppUsername != "env-app" {
		t.Fatalf("unexpected usernames: admin=%s app=%s", cfg.AdminUsername, cfg.AppUsername)
	}
	if cfg.AppAccessTTL != 5*time.Minute || cfg.TokenAccessTTL != 8*time.Minute {
		t.Fatalf("unexpected access TTLs: app=%s token=%s", cfg.AppAccessTTL, cfg.TokenAccessTTL)
	}
	if cfg.AppMaxAccessTTL != 2*24*time.Hour || cfg.TokenRefreshTTL != 5*24*time.Hour {
		t.Fatalf("unexpected max/refresh TTLs: appMax=%s tokenRefresh=%s", cfg.AppMaxAccessTTL, cfg.TokenRefreshTTL)
	}
	if cfg.AppRotateDeviceToken || cfg.TokenRotateRefresh {
		t.Fatalf("expected rotate flags false: app=%v token=%v", cfg.AppRotateDeviceToken, cfg.TokenRotateRefresh)
	}
	if cfg.CleanupRetention != 6*time.Hour || cfg.CleanupCron != "0 */10 * * * *" {
		t.Fatalf("unexpected cleanup overrides: retention=%s cron=%s", cfg.CleanupRetention, cfg.CleanupCron)
	}
}

func TestLoadCLIServiceLayoutOverridesPathAndPortEnv(t *testing.T) {
	tempDir := t.TempDir()
	chdirTemp(t, tempDir)
	configDir := t.TempDir()
	dataDir := t.TempDir()
	stateDir := t.TempDir()
	logDir := t.TempDir()
	t.Setenv("SERVER_PORT", "28080")
	t.Setenv("AUTH_DB_PATH", "/tmp/ignored-auth.db")
	t.Setenv("AUTH_ISSUER", "http://env.example:28080")
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)

	cfg, err := LoadWithArgs([]string{
		"--config-dir", configDir,
		"--data-dir", dataDir,
		"--state-dir", stateDir,
		"--log-dir", logDir,
		"--port", "19090",
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ConfigDir != configDir || cfg.DataDir != dataDir || cfg.StateDir != stateDir || cfg.LogDir != logDir {
		t.Fatalf("layout flags not captured: config=%s data=%s state=%s log=%s", cfg.ConfigDir, cfg.DataDir, cfg.StateDir, cfg.LogDir)
	}
	if cfg.ServerPort != 19090 {
		t.Fatalf("ServerPort = %d, want CLI port", cfg.ServerPort)
	}
	if want := dataDir + string(os.PathSeparator) + "auth.db"; cfg.DBPath != want {
		t.Fatalf("DBPath = %q, want %q", cfg.DBPath, want)
	}
	if cfg.Issuer != "http://env.example:28080" {
		t.Fatalf("Issuer = %q, want env issuer", cfg.Issuer)
	}
}

func TestLoadIgnoresBackendPortForServerPort(t *testing.T) {
	tempDir := t.TempDir()
	chdirTemp(t, tempDir)
	t.Setenv("SERVER_PORT", "")
	t.Setenv("BACKEND_PORT", "11952")
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ServerPort != builtInDefaults.ServerPort {
		t.Fatalf("expected backend port env to be ignored, got: %d", cfg.ServerPort)
	}
}

func TestDocumentedDevBcryptPassesValidation(t *testing.T) {
	if !bcryptPattern.MatchString(documentedDevBcrypt) {
		t.Fatalf("documented dev bcrypt is invalid: %s", documentedDevBcrypt)
	}

	tempDir := t.TempDir()
	chdirTemp(t, tempDir)
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.AdminPasswordBcrypt != documentedDevBcrypt {
		t.Fatalf("unexpected admin bcrypt: %s", cfg.AdminPasswordBcrypt)
	}
}
