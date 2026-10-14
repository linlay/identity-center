package config

import (
	"fmt"
	"strings"
	"time"
)

type EmailConfig struct {
	LoginEnabled, BindEnabled                                                bool
	Host, TLSMode, Username, Password, From, FromName, DigestKey             string
	Port                                                                     int
	Timeout                                                                  time.Duration
	EmailHour, EmailDay, AccountHour, AccountDay, IPHour, IPDay, FailureHour int
}

func loadEmailConfig() (EmailConfig, error) {
	c := EmailConfig{
		LoginEnabled: envBool("AUTH_EMAIL_LOGIN_ENABLED", false), BindEnabled: envBool("AUTH_EMAIL_BIND_ENABLED", false),
		Host: env("AUTH_SMTP_HOST", ""), Port: envInt("AUTH_SMTP_PORT", 465), TLSMode: env("AUTH_SMTP_TLS", "tls"),
		Username: env("AUTH_SMTP_USERNAME", ""), Password: env("AUTH_SMTP_PASSWORD", ""),
		From: env("AUTH_SMTP_FROM", ""), FromName: env("AUTH_SMTP_FROM_NAME", "Zenmind"), DigestKey: env("AUTH_EMAIL_DIGEST_KEY", ""),
		Timeout:   time.Duration(envInt("AUTH_SMTP_TIMEOUT_SECONDS", 5)) * time.Second,
		EmailHour: envInt("AUTH_EMAIL_SEND_EMAIL_HOUR", 5), EmailDay: envInt("AUTH_EMAIL_SEND_EMAIL_DAY", 10),
		AccountHour: envInt("AUTH_EMAIL_SEND_ACCOUNT_HOUR", 10), AccountDay: envInt("AUTH_EMAIL_SEND_ACCOUNT_DAY", 20),
		IPHour: envInt("AUTH_EMAIL_SEND_IP_HOUR", 30), IPDay: envInt("AUTH_EMAIL_SEND_IP_DAY", 100),
		FailureHour: envInt("AUTH_EMAIL_FAILURE_HOUR", 20),
	}
	if c.LoginEnabled || c.BindEnabled {
		if err := c.validate(); err != nil {
			return c, err
		}
	}
	return c, nil
}

func (c EmailConfig) validate() error {
	if c.Port < 1 || c.Port > 65535 || c.Timeout < time.Second || c.Timeout > 10*time.Second || (c.TLSMode != "tls" && c.TLSMode != "starttls") {
		return fmt.Errorf("invalid SMTP port, TLS mode or timeout (1-10 seconds)")
	}
	for _, v := range []int{c.EmailHour, c.EmailDay, c.AccountHour, c.AccountDay, c.IPHour, c.IPDay, c.FailureHour} {
		if v <= 0 {
			return fmt.Errorf("email limits must be positive")
		}
	}
	if strings.ContainsAny(c.Host+c.From+c.FromName, "\r\n") {
		return fmt.Errorf("invalid SMTP identity")
	}
	if c.Host == "" || c.From == "" || c.Username == "" || c.Password == "" || len(c.DigestKey) < 32 {
		return fmt.Errorf("email authentication requires SMTP and a digest key of at least 32 bytes")
	}
	return nil
}

func (c EmailConfig) Ready() bool {
	return c.validate() == nil
}
