package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-center/backend/internal/config"
)

func TestSMTPFinalAcceptanceTLSAndUnknownResult(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	for _, mode := range []string{"accepted", "accepted-starttls", "rejected", "unknown", "bad-certificate", "no-starttls"} {
		t.Run(mode, func(t *testing.T) {
			accepted := strings.HasPrefix(mode, "accepted")
			var listener net.Listener
			var err error
			if mode == "accepted-starttls" || mode == "no-starttls" {
				listener, err = net.Listen("tcp", "127.0.0.1:0")
			} else {
				listener, err = tls.Listen("tcp", "127.0.0.1:0", serverTLS)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- ""
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
				reply := func(s string) { _, _ = fmt.Fprint(writer, s+"\r\n"); _ = writer.Flush() }
				reply("220 smtp-test")
				secured := mode != "accepted-starttls"
				var body strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						done <- body.String()
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						reply("250-smtp-test")
						if !secured {
							reply("250-STARTTLS")
						}
						reply("250 AUTH PLAIN")
					case strings.HasPrefix(line, "STARTTLS"):
						reply("220 ready for TLS")
						secureConn := tls.Server(conn, serverTLS)
						if err := secureConn.Handshake(); err != nil {
							done <- body.String()
							return
						}
						conn = secureConn
						reader, writer = bufio.NewReader(conn), bufio.NewWriter(conn)
						secured = true
					case strings.HasPrefix(line, "AUTH"):
						reply("235 authenticated")
					case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						reply("250 ok")
					case strings.HasPrefix(line, "DATA"):
						reply("354 continue")
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								done <- body.String()
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						if accepted {
							reply("250 accepted")
						} else if mode == "rejected" {
							reply("550 rejected")
						} // unknown: no final reply
					default:
						reply("250 ok")
					}
				}
			}()
			_, portRaw, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portRaw)
			host := "127.0.0.1"
			tlsMode := "tls"
			if mode == "bad-certificate" {
				host = "localhost"
			}
			if mode == "accepted-starttls" || mode == "no-starttls" {
				tlsMode = "starttls"
			}
			cfg := config.EmailConfig{Host: host, Port: port, TLSMode: tlsMode, Username: "test", Password: "test", From: "sender@example.com", FromName: "Zenmind", DigestKey: strings.Repeat("x", 32), Timeout: time.Second,
				EmailHour: 1, EmailDay: 1, AccountHour: 1, AccountDay: 1, IPHour: 1, IPDay: 1, FailureHour: 1}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			started := time.Now()
			err = sendAccountEmail(ctx, cfg, "Alice+tag@Example.COM", "bind", "123456")
			if accepted && err != nil {
				t.Fatal("accepted SMTP failed", err)
			}
			if !accepted && err == nil {
				t.Fatal("unconfirmed SMTP accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("SMTP request exceeded timeout bound")
			}
			_ = listener.Close()
			message := <-done
			if accepted {
				for _, b := range []byte(message) {
					if b > 127 {
						t.Fatal("non-ASCII message sent without 8BITMIME")
					}
				}
				mailMessage, err := mail.ReadMessage(strings.NewReader(message))
				if err != nil {
					t.Fatal(err)
				}
				if mailMessage.Header.Get("Content-Transfer-Encoding") != "quoted-printable" || mailMessage.Header.Get("Content-Type") != "text/plain; charset=utf-8" || mailMessage.Header.Get("To") != "Alice+tag@Example.COM" {
					t.Fatal("incorrect message headers")
				}
				body, err := io.ReadAll(quotedprintable.NewReader(mailMessage.Body))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), "您的绑定邮箱验证码是：123456。5 分钟内有效。") || !strings.Contains(string(body), "Your code to bind your email is 123456.") || !strings.Contains(string(body), "If you did not request this, ignore this email.") {
					t.Fatal("missing bilingual plain-text content")
				}
			}
		})
	}
}
