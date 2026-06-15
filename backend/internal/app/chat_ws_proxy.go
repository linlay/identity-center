package app

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const chatWSProxyDialTimeout = 5 * time.Second
const apAPIPathPrefix = "/ap/api"
const appAuthScopeHeader = "X-Zenmind-Auth-Scope"
const appAuthScopeValue = "app"

var chatWSStripHeaders = map[string]struct{}{
	"authorization":            {},
	"connection":               {},
	"cookie":                   {},
	"host":                     {},
	"proxy-authorization":      {},
	"sec-websocket-extensions": {},
	"transfer-encoding":        {},
	"upgrade":                  {},
}

var apHTTPStripHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"upgrade":             {},
}

func (s *Server) handleChatWebSocketProxy(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		writeAPIError(w, http.StatusBadRequest, "websocket upgrade required")
		return
	}

	if _, err := s.authenticateAppAccessToken(apAppAccessToken(r)); err != nil {
		writeAppAuthError(w)
		return
	}

	upstreamURL, err := parseChatWSUpstreamURL(s.cfg.APUpstreamBaseURL, s.cfg.ChatWSUpstreamURL, r.URL, s.cfg.APUpstreamAccessToken)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "chat websocket upstream unavailable")
		return
	}

	if err := proxyChatWebSocketUpgrade(w, r, upstreamURL); err != nil {
		s.logger.Printf("chat websocket proxy failed: %v", err)
	}
}

func (s *Server) handleAPAPIProxy(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticateAppAccessToken(apAppAccessToken(r)); err != nil {
		writeAppAuthError(w)
		return
	}

	proxy, err := s.apAPIProxyHandler()
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "chat api upstream unavailable")
		return
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) apAPIProxyHandler() (http.Handler, error) {
	s.apAPIProxyOnce.Do(func() {
		s.apAPIProxy, s.apAPIProxyErr = s.newAPAPIProxy()
	})
	return s.apAPIProxy, s.apAPIProxyErr
}

func (s *Server) newAPAPIProxy() (http.Handler, error) {
	upstreamBase, err := parseAPUpstreamBaseURL(s.cfg.APUpstreamBaseURL, s.cfg.ChatWSUpstreamURL)
	if err != nil {
		return nil, err
	}
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			originalTLS := req.TLS != nil
			upstreamURL := buildAPAPIUpstreamURL(upstreamBase, req.URL)
			req.URL.Scheme = upstreamURL.Scheme
			req.URL.Host = upstreamURL.Host
			req.URL.Path = upstreamURL.Path
			req.URL.RawPath = upstreamURL.RawPath
			req.URL.RawQuery = upstreamURL.RawQuery
			req.URL.Fragment = ""
			req.Host = upstreamURL.Host
			stripHeaders(req.Header, apHTTPStripHeaders)
			setBearerHeader(req.Header, s.cfg.APUpstreamAccessToken)
			addForwardedHeadersFromValues(req, originalHost, originalTLS)
		},
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			s.logger.Printf("chat api proxy failed: %v", proxyErr)
			writeAPIError(rw, http.StatusBadGateway, "chat api upstream unavailable")
		},
	}, nil
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerContainsToken(r.Header.Get("Connection"), "upgrade")
}

func writeAppAuthError(w http.ResponseWriter) {
	w.Header().Set(appAuthScopeHeader, appAuthScopeValue)
	writeAPIError(w, http.StatusUnauthorized, "unauthorized")
}

func headerContainsToken(value string, token string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}
	return false
}

func apAppAccessToken(r *http.Request) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	query := r.URL.Query()
	if token := strings.TrimSpace(query.Get("token")); token != "" {
		return token
	}
	return strings.TrimSpace(query.Get("access_token"))
}

func parseAPUpstreamBaseURL(rawBaseURL string, legacyWSURL string) (*url.URL, error) {
	rawBaseURL = strings.TrimSpace(rawBaseURL)
	if rawBaseURL == "" {
		rawBaseURL = deriveAPUpstreamBaseURLFromWSURL(legacyWSURL)
	}
	if rawBaseURL == "" {
		return nil, fmt.Errorf("missing AP_UPSTREAM_BASE_URL")
	}
	parsed, err := url.Parse(rawBaseURL)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("missing upstream host")
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", parsed.Scheme)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func deriveAPUpstreamBaseURLFromWSURL(rawValue string) string {
	rawValue = strings.TrimSpace(rawValue)
	if rawValue == "" {
		return ""
	}
	parsed, err := url.Parse(rawValue)
	if err != nil || parsed.Host == "" {
		return ""
	}
	switch parsed.Scheme {
	case "ws":
		parsed.Scheme = "http"
	case "wss":
		parsed.Scheme = "https"
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func parseChatWSUpstreamURL(rawBaseURL string, legacyWSURL string, clientURL *url.URL, upstreamAccessToken string) (*url.URL, error) {
	if strings.TrimSpace(rawBaseURL) == "" && strings.TrimSpace(legacyWSURL) != "" {
		parsed, err := parseLegacyChatWSUpstreamURL(legacyWSURL)
		if err != nil {
			return nil, err
		}
		return appendSanitizedQuery(parsed, clientURL, upstreamAccessToken), nil
	}

	baseURL, err := parseAPUpstreamBaseURL(rawBaseURL, legacyWSURL)
	if err != nil {
		return nil, err
	}
	parsed := *baseURL
	parsed.Path = joinURLPath(baseURL.Path, "/ws")
	return appendSanitizedQuery(&parsed, clientURL, upstreamAccessToken), nil
}

func parseLegacyChatWSUpstreamURL(rawValue string) (*url.URL, error) {
	rawValue = strings.TrimSpace(rawValue)
	if rawValue == "" {
		return nil, fmt.Errorf("missing CHAT_WS_UPSTREAM_URL")
	}
	parsed, err := url.Parse(rawValue)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("missing upstream host")
	}
	switch parsed.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", parsed.Scheme)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func appendSanitizedQuery(parsed *url.URL, clientURL *url.URL, upstreamAccessToken string) *url.URL {
	query := parsed.Query()
	if clientURL != nil {
		for key, values := range clientURL.Query() {
			if isWebSocketAuthQueryKey(key) {
				continue
			}
			for _, value := range values {
				query.Add(key, value)
			}
		}
	}
	if token := strings.TrimSpace(upstreamAccessToken); token != "" {
		query.Set("token", token)
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed
}

func buildAPAPIUpstreamURL(baseURL *url.URL, clientURL *url.URL) *url.URL {
	upstreamURL := *baseURL
	suffix := strings.TrimPrefix(clientURL.Path, apAPIPathPrefix)
	if suffix == "" {
		suffix = "/"
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	upstreamURL.Path = joinURLPath(baseURL.Path, "/api"+suffix)
	upstreamURL.RawPath = ""
	if clientURL.RawPath != "" {
		rawSuffix := strings.TrimPrefix(clientURL.EscapedPath(), apAPIPathPrefix)
		if rawSuffix == "" {
			rawSuffix = "/"
		}
		if !strings.HasPrefix(rawSuffix, "/") {
			rawSuffix = "/" + rawSuffix
		}
		upstreamURL.RawPath = joinURLPath(baseURL.EscapedPath(), "/api"+rawSuffix)
	}
	return appendSanitizedQuery(&upstreamURL, clientURL, "")
}

func joinURLPath(left string, right string) string {
	left = strings.TrimRight(left, "/")
	right = "/" + strings.TrimLeft(right, "/")
	if left == "" {
		return right
	}
	return left + right
}

func isWebSocketAuthQueryKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "token", "access_token":
		return true
	default:
		return false
	}
}

func proxyChatWebSocketUpgrade(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL) error {
	upstreamConn, err := dialChatWSUpstream(upstreamURL)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "chat websocket upstream unavailable")
		return err
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		writeAPIError(w, http.StatusInternalServerError, "websocket hijack unavailable")
		return fmt.Errorf("response writer does not support hijacking")
	}

	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		return err
	}

	if err := writeChatWSUpgradeRequest(upstreamConn, r, upstreamURL); err != nil {
		_ = upstreamConn.Close()
		_ = clientConn.Close()
		return err
	}

	if buffered := clientRW.Reader.Buffered(); buffered > 0 {
		if _, err := io.CopyN(upstreamConn, clientRW.Reader, int64(buffered)); err != nil {
			_ = upstreamConn.Close()
			_ = clientConn.Close()
			return err
		}
	}

	go proxyChatWSBytes(upstreamConn, clientConn)
	go proxyChatWSBytes(clientConn, upstreamConn)
	return nil
}

func dialChatWSUpstream(upstreamURL *url.URL) (net.Conn, error) {
	address := upstreamURL.Host
	if upstreamURL.Port() == "" {
		address = net.JoinHostPort(upstreamURL.Hostname(), defaultChatWSUpstreamPort(upstreamURL.Scheme))
	}

	dialer := net.Dialer{Timeout: chatWSProxyDialTimeout}
	switch upstreamURL.Scheme {
	case "https", "wss":
		return tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{ServerName: upstreamURL.Hostname()})
	default:
		return dialer.Dial("tcp", address)
	}
}

func defaultChatWSUpstreamPort(scheme string) string {
	switch scheme {
	case "https", "wss":
		return "443"
	default:
		return "80"
	}
}

func writeChatWSUpgradeRequest(conn net.Conn, r *http.Request, upstreamURL *url.URL) error {
	writer := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(writer, "GET %s HTTP/1.1\r\n", upstreamURL.RequestURI()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Host: %s\r\n", upstreamURL.Host); err != nil {
		return err
	}
	if _, err := writer.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\n"); err != nil {
		return err
	}

	for key, values := range r.Header {
		if _, strip := chatWSStripHeaders[strings.ToLower(key)]; strip {
			continue
		}
		if strings.EqualFold(key, "Sec-WebSocket-Protocol") && containsBearerWebSocketProtocol(values) {
			continue
		}
		for _, value := range values {
			if _, err := fmt.Fprintf(writer, "%s: %s\r\n", key, value); err != nil {
				return err
			}
		}
	}

	if host := strings.TrimSpace(r.Host); host != "" {
		if _, err := fmt.Fprintf(writer, "X-Forwarded-Host: %s\r\n", host); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "X-Forwarded-Proto: %s\r\n", forwardedProto(r)); err != nil {
		return err
	}
	if remoteIP := remoteAddrIP(r.RemoteAddr); remoteIP != "" {
		if _, err := fmt.Fprintf(writer, "X-Forwarded-For: %s\r\n", remoteIP); err != nil {
			return err
		}
	}
	if _, err := writer.WriteString("\r\n"); err != nil {
		return err
	}
	return writer.Flush()
}

func stripHeaders(headers http.Header, stripSet map[string]struct{}) {
	for key := range headers {
		if _, strip := stripSet[strings.ToLower(key)]; strip {
			headers.Del(key)
		}
	}
}

func setBearerHeader(headers http.Header, token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	headers.Set("Authorization", "Bearer "+token)
}

func addForwardedHeadersFromValues(req *http.Request, host string, tlsEnabled bool) {
	if forwardedHost := strings.TrimSpace(host); forwardedHost != "" {
		req.Header.Set("X-Forwarded-Host", forwardedHost)
	}
	if tlsEnabled {
		req.Header.Set("X-Forwarded-Proto", "https")
		return
	}
	req.Header.Set("X-Forwarded-Proto", "http")
}

func containsBearerWebSocketProtocol(values []string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			normalized := strings.ToLower(strings.TrimSpace(item))
			if strings.HasPrefix(normalized, "bearer.") || strings.HasPrefix(normalized, "bearer ") {
				return true
			}
		}
	}
	return false
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func proxyChatWSBytes(dst net.Conn, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}
