package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"identity-center/backend/internal/config"
	"identity-center/backend/internal/store"
)

// Success means the final DATA reply was accepted. QUIT failure cannot undo acceptance.
func sendAccountEmail(ctx context.Context, c config.EmailConfig, to, purpose, code string) error {
	if !c.Ready() {
		return store.ErrEmailSend
	}
	to, _, err := store.NormalizeEmail(to)
	if err != nil {
		return err
	}
	from, _, err := store.NormalizeEmail(c.From)
	if err != nil {
		return err
	}
	words := map[string][2]string{"login": {"登录", "sign in"}, "bind": {"绑定邮箱", "bind your email"}, "unbind": {"解绑邮箱", "unbind your email"}}
	word, ok := words[purpose]
	if !ok || len(code) != 6 || strings.ContainsAny(c.FromName, "\r\n") {
		return store.ErrEmailFormat
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return store.ErrEmailFormat
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, fmt.Sprint(c.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	tlsConfig := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.TLSMode == "tls" {
		secured := tls.Client(conn, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = secured
	} else if c.TLSMode != "starttls" {
		return store.ErrEmailSend
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if c.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return store.ErrEmailSend
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	subject := mime.QEncoding.Encode("utf-8", "Zenmind "+word[0]+"验证码 / Verification code")
	body := fmt.Sprintf("您的%s验证码是：%s。5 分钟内有效。请使用最新验证码。如非本人操作，请忽略此邮件。\r\n\r\nYour code to %s is %s. It expires in 5 minutes. Use the latest code. If you did not request this, ignore this email.\r\n", word[0], code, word[1], code)
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nDate: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s", (&mail.Address{Name: c.FromName, Address: from}).String(), to, time.Now().UTC().Format(time.RFC1123Z), subject, body)
	if _, err := writer.Write([]byte(message)); err != nil {
		return err
	}
	return writer.Close()
}
