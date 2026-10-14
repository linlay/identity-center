package config

import "testing"

func setValidEmailEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"AUTH_EMAIL_LOGIN_ENABLED": "false", "AUTH_EMAIL_BIND_ENABLED": "false",
		"AUTH_SMTP_HOST": "smtp.example.test", "AUTH_SMTP_PORT": "465", "AUTH_SMTP_TLS": "tls",
		"AUTH_SMTP_USERNAME": "sender", "AUTH_SMTP_PASSWORD": "test-password",
		"AUTH_SMTP_FROM": "sender@example.test", "AUTH_SMTP_FROM_NAME": "Test",
		"AUTH_SMTP_TIMEOUT_SECONDS": "5", "AUTH_EMAIL_DIGEST_KEY": "test-only-digest-key-longer-than-32-bytes",
		"AUTH_EMAIL_SEND_EMAIL_HOUR": "5", "AUTH_EMAIL_SEND_EMAIL_DAY": "10",
		"AUTH_EMAIL_SEND_ACCOUNT_HOUR": "10", "AUTH_EMAIL_SEND_ACCOUNT_DAY": "20",
		"AUTH_EMAIL_SEND_IP_HOUR": "30", "AUTH_EMAIL_SEND_IP_DAY": "100", "AUTH_EMAIL_FAILURE_HOUR": "20",
	} {
		t.Setenv(key, value)
	}
}

func TestDisabledEmailConfigurationDoesNotBlockCoreStartup(t *testing.T) {
	setValidEmailEnvironment(t)
	t.Setenv("AUTH_ADMIN_PASSWORD_BCRYPT", documentedDevBcrypt)
	for _, test := range []struct{ key, value string }{
		{"AUTH_SMTP_PORT", "0"},
		{"AUTH_SMTP_TIMEOUT_SECONDS", "30"},
		{"AUTH_SMTP_TLS", "none"},
		{"AUTH_EMAIL_SEND_IP_DAY", "0"},
		{"AUTH_SMTP_FROM_NAME", "invalid\r\nidentity"},
		{"AUTH_EMAIL_DIGEST_KEY", ""},
	} {
		t.Run(test.key, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			cfg, err := LoadWithArgs([]string{"--config-dir", t.TempDir()})
			if err != nil {
				t.Fatalf("disabled email blocked core configuration: %v", err)
			}
			if cfg.Email.Ready() {
				t.Fatal("invalid email configuration is ready for use")
			}
		})
	}
}

func TestEnabledEmailRequiresValidConfiguration(t *testing.T) {
	setValidEmailEnvironment(t)
	for _, flag := range []string{"AUTH_EMAIL_LOGIN_ENABLED", "AUTH_EMAIL_BIND_ENABLED"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv(flag, "true")
			cfg, err := loadEmailConfig()
			if err != nil || !cfg.Ready() {
				t.Fatalf("valid enabled email configuration rejected: %v", err)
			}
			for _, test := range []struct{ key, value string }{
				{"AUTH_SMTP_TIMEOUT_SECONDS", "30"},
				{"AUTH_EMAIL_SEND_IP_DAY", "0"},
				{"AUTH_EMAIL_DIGEST_KEY", "short-key"},
			} {
				t.Run(test.key, func(t *testing.T) {
					t.Setenv(test.key, test.value)
					if _, err := loadEmailConfig(); err == nil {
						t.Fatal("enabled email accepted invalid configuration")
					}
				})
			}
		})
	}
}

func TestValidEmailRemainsReadyWithEntryPointsDisabled(t *testing.T) {
	setValidEmailEnvironment(t)
	cfg, err := loadEmailConfig()
	if err != nil || cfg.LoginEnabled || cfg.BindEnabled || !cfg.Ready() {
		t.Fatalf("valid rollback configuration unavailable for unbinding: %v", err)
	}
}
