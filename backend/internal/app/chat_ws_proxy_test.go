package app

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"zenmind-app-server/backend/internal/config"
	"zenmind-app-server/backend/internal/db"
	"zenmind-app-server/backend/internal/security"
	"zenmind-app-server/backend/internal/store"
)

func setChatWebSocketUpgradeHeaders(h http.Header) {
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	h.Set("Sec-WebSocket-Version", "13")
}

func TestChatWebSocketProxyRejectsInvalidAppToken(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/ap/ws?token=invalid", nil)
	setChatWebSocketUpgradeHeaders(req.Header)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get(appAuthScopeHeader) != appAuthScopeValue {
		t.Fatalf("expected app auth scope header, got %q", rr.Header().Get(appAuthScopeHeader))
	}
}

func TestChatWebSocketProxyRequiresUpstream(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "4a85f28d-b31f-4026-8daf-22d6de52360a")

	req := httptest.NewRequest(http.MethodGet, "/ap/ws?token="+url.QueryEscape(token), nil)
	setChatWebSocketUpgradeHeaders(req.Header)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable status, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestChatWebSocketProxyStripsAppTokenBeforeUpstream(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "191b07fd-a73b-4352-b1f3-5e36dfd1888b")
	upstreamAddr, captured, stopUpstream := startRawChatWebSocketUpstream(t)
	defer stopUpstream()
	s.cfg.ChatWSUpstreamURL = "http://" + upstreamAddr + "/ws?server=1"

	server := httptest.NewServer(s.Handler())
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	conn, err := net.Dial("tcp", serverURL.Host)
	if err != nil {
		t.Fatalf("dial app server: %v", err)
	}
	defer conn.Close()

	requestTarget := "/ap/ws?token=" + url.QueryEscape(token) + "&access_token=strip-me&foo=bar"
	if _, err := fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer %s\r\nCookie: secret=1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
		requestTarget,
		serverURL.Host,
		token,
	); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status 101, got %d", response.StatusCode)
	}

	var upstreamReq *http.Request
	select {
	case upstreamReq = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}

	if upstreamReq.URL.Path != "/ws" {
		t.Fatalf("expected upstream path /ws, got %s", upstreamReq.URL.Path)
	}
	query := upstreamReq.URL.Query()
	if query.Get("foo") != "bar" || query.Get("server") != "1" {
		t.Fatalf("expected preserved non-auth query, got %s", upstreamReq.URL.RawQuery)
	}
	if query.Get("token") != "" || query.Get("access_token") != "" {
		t.Fatalf("expected auth query to be stripped, got %s", upstreamReq.URL.RawQuery)
	}
	if upstreamReq.Header.Get("Authorization") != "" {
		t.Fatalf("expected Authorization header to be stripped")
	}
	if upstreamReq.Header.Get("Cookie") != "" {
		t.Fatalf("expected Cookie header to be stripped")
	}
	if upstreamReq.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("expected Sec-WebSocket-Extensions header to be stripped")
	}
}

func TestChatWebSocketProxyInjectsUpstreamAccessToken(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "71eef020-c554-48ee-85f6-fde2f24a2b77")
	upstreamAddr, captured, stopUpstream := startRawChatWebSocketUpstream(t)
	defer stopUpstream()
	s.cfg.ChatWSUpstreamURL = "http://" + upstreamAddr + "/ws?server=1"
	s.cfg.APUpstreamAccessToken = "upstream-token"

	server := httptest.NewServer(s.Handler())
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	conn, err := net.Dial("tcp", serverURL.Host)
	if err != nil {
		t.Fatalf("dial app server: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn,
		"GET /ap/ws?token=%s&foo=bar HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer %s\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		url.QueryEscape(token),
		serverURL.Host,
		token,
	); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status 101, got %d", response.StatusCode)
	}

	var upstreamReq *http.Request
	select {
	case upstreamReq = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}

	query := upstreamReq.URL.Query()
	if query.Get("token") != "upstream-token" || query.Get("foo") != "bar" || query.Get("server") != "1" {
		t.Fatalf("unexpected upstream query %s", upstreamReq.URL.RawQuery)
	}
	if upstreamReq.Header.Get("Authorization") != "" {
		t.Fatalf("expected mobile Authorization header to be stripped")
	}
}

func TestAPAPIProxyRejectsInvalidAppToken(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/ap/api/chat?token=invalid", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get(appAuthScopeHeader) != appAuthScopeValue {
		t.Fatalf("expected app auth scope header, got %q", rr.Header().Get(appAuthScopeHeader))
	}
}

func TestAPAPIProxyRequiresUpstream(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "8c108bcc-9129-4d4a-a8ab-f6622f631109")

	req := httptest.NewRequest(http.MethodGet, "/ap/api/chat?chatId=c1&token="+url.QueryEscape(token), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway status, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPAPIProxyStreamsRequestAndStripsMobileAuth(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "7ae0f089-72ca-4401-90b6-e147deca27be")
	captured := make(chan *http.Request, 1)
	bodyCh := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		bodyCh <- string(body)
		captured <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	s.cfg.APUpstreamBaseURL = upstream.URL

	req := httptest.NewRequest(
		http.MethodPost,
		"/ap/api/read?token="+url.QueryEscape(token)+"&access_token=strip-me&chatId=c1",
		bytes.NewBufferString(`{"chatId":"c1"}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "secret=1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var upstreamReq *http.Request
	select {
	case upstreamReq = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
	if upstreamReq.Method != http.MethodPost || upstreamReq.URL.Path != "/api/read" {
		t.Fatalf("unexpected upstream request %s %s", upstreamReq.Method, upstreamReq.URL.Path)
	}
	query := upstreamReq.URL.Query()
	if query.Get("chatId") != "c1" || query.Get("token") != "" || query.Get("access_token") != "" {
		t.Fatalf("unexpected upstream query %s", upstreamReq.URL.RawQuery)
	}
	if upstreamReq.Header.Get("Authorization") != "" {
		t.Fatalf("expected Authorization header to be stripped")
	}
	if upstreamReq.Header.Get("Cookie") != "" {
		t.Fatalf("expected Cookie header to be stripped")
	}
	if upstreamReq.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type to be preserved, got %q", upstreamReq.Header.Get("Content-Type"))
	}
	select {
	case body := <-bodyCh:
		if body != `{"chatId":"c1"}` {
			t.Fatalf("unexpected upstream body %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream body")
	}
}

func TestAPAPIProxyInjectsUpstreamAccessToken(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "96988938-f662-4e2f-837d-38ff5290aec5")
	captured := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	s.cfg.APUpstreamBaseURL = upstream.URL
	s.cfg.APUpstreamAccessToken = "upstream-token"

	req := httptest.NewRequest(
		http.MethodGet,
		"/ap/api/chat?token="+url.QueryEscape(token)+"&access_token=strip-me&chatId=c1",
		nil,
	)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var upstreamReq *http.Request
	select {
	case upstreamReq = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
	if upstreamReq.URL.Path != "/api/chat" {
		t.Fatalf("unexpected upstream path %s", upstreamReq.URL.Path)
	}
	query := upstreamReq.URL.Query()
	if query.Get("chatId") != "c1" || query.Get("token") != "" || query.Get("access_token") != "" {
		t.Fatalf("unexpected upstream query %s", upstreamReq.URL.RawQuery)
	}
	if upstreamReq.Header.Get("Authorization") != "Bearer upstream-token" {
		t.Fatalf("expected upstream Authorization header, got %q", upstreamReq.Header.Get("Authorization"))
	}
}

func TestAPAPIProxyPreservesEscapedPath(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "e32d905a-003d-40c2-a59b-29d29de6eef6")
	captured := make(chan *url.URL, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		copied := *r.URL
		captured <- &copied
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	s.cfg.APUpstreamBaseURL = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/ap/api/files/a%2Fb?token="+url.QueryEscape(token)+"&q=x%20y", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d body=%s", rr.Code, rr.Body.String())
	}
	var upstreamURL *url.URL
	select {
	case upstreamURL = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
	if upstreamURL.Path != "/api/files/a/b" || upstreamURL.EscapedPath() != "/api/files/a%2Fb" {
		t.Fatalf("expected escaped upstream path /api/files/a%%2Fb, got path=%q escaped=%q", upstreamURL.Path, upstreamURL.EscapedPath())
	}
	if upstreamURL.Query().Get("q") != "x y" || upstreamURL.Query().Get("token") != "" {
		t.Fatalf("unexpected upstream query %s", upstreamURL.RawQuery)
	}
}

func TestAPAPIProxyPreservesUpstreamNotFound(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "7720dfdd-d833-4a96-8f4d-df17933ce235")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()
	s.cfg.APUpstreamBaseURL = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/ap/api/chat?chatId=missing", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected upstream 404 to pass through, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "404 page not found\n" {
		t.Fatalf("expected upstream not found body, got %q", rr.Body.String())
	}
}

func TestAPAPIProxyDoesNotMarkUpstreamUnauthorizedAsAppAuth(t *testing.T) {
	s, cleanup := newChatWebSocketProxyTestServer(t)
	defer cleanup()
	token := createChatWebSocketProxyBearerToken(t, s, "872a3986-d7cd-4ac9-9d72-0d91be1f1f64")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
	}))
	defer upstream.Close()
	s.cfg.APUpstreamBaseURL = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/ap/api/chat?chatId=c1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected upstream unauthorized status, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get(appAuthScopeHeader) != "" {
		t.Fatalf("expected no app auth scope header for upstream 401, got %q", rr.Header().Get(appAuthScopeHeader))
	}
}

func newChatWebSocketProxyTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	root := t.TempDir()
	conn, err := db.Open(filepath.Join(root, "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitEmbeddedSchema(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("init schema: %v", err)
	}
	s, err := New(&config.Config{
		Issuer:               "http://127.0.0.1:8080",
		AppUsername:          "app",
		AppAccessTTL:         time.Hour,
		AppMaxAccessTTL:      24 * time.Hour,
		AppRotateDeviceToken: true,
		CleanupRetention:     time.Hour,
		CleanupCron:          "0 0 * * * *",
	}, store.New(conn), security.NewKeyManager(conn), log.New(io.Discard, "", 0))
	if err != nil {
		_ = conn.Close()
		t.Fatalf("new server: %v", err)
	}
	return s, func() {
		s.Close()
		_ = conn.Close()
	}
}

func createChatWebSocketProxyBearerToken(t *testing.T, s *Server, deviceID string) string {
	t.Helper()
	tokenHash, err := bcrypt.GenerateFromPassword([]byte("mobile-device-token"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash device token: %v", err)
	}
	if _, err := s.store.EnsureActiveDeviceWithID(deviceID, "Mobile Test Device", string(tokenHash)); err != nil {
		t.Fatalf("create app device: %v", err)
	}
	token, _, _, err := s.issueAppAccessToken(s.cfg.AppUsername, deviceID, time.Hour)
	if err != nil {
		t.Fatalf("issue app token: %v", err)
	}
	return token
}

func startRawChatWebSocketUpstream(t *testing.T) (string, <-chan *http.Request, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	captured := make(chan *http.Request, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Errorf("read upstream request: %v", err)
			return
		}
		captured <- req
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	}()

	return listener.Addr().String(), captured, func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}
