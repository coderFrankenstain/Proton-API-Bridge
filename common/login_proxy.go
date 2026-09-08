package common

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
)

// Proton scores POST /auth/v4 by the reputation of the client IP. A
// datacenter egress IP that logs many different accounts in is challenged
// with CAPTCHA (Code=9001, "human verification required") and, after a few
// retries, rate limited. Reusable-credential logins, token refreshes and
// Drive data traffic are not scored the same way and keep working from the
// same IP. So only the password-login flow (SRP auth, 2FA, user/address/salt
// fetch and the Drive bootstrap) is worth routing through a proxy; everything
// else must stay on the direct connection, not least because residential
// proxy traffic is billed per byte.
//
// The routing is per request and driven by the request context: callers mark
// a context with WithLoginProxy and every request (and retry) carrying that
// context goes through Config.LoginProxyURL. NewProtonDrive does that marking
// itself for the password-login path, so library users only set the URL.

type loginProxyCtxKey struct{}

// LoginProxyStats accumulates the requests routed through the login proxy so
// callers can log, and alert on, how much proxy traffic one login used.
//
// Bytes counts request bodies as declared by Content-Length plus response
// bodies as read by the caller (after the transport's transparent gzip
// decoding), so it is an upper bound of the wire volume rather than an exact
// figure. Fields are accessed atomically; keep them first for 32-bit alignment.
type LoginProxyStats struct {
	Requests int64
	Bytes    int64
}

// WithLoginProxy marks ctx so that every request carrying it (including
// resty retries, which reuse the context) is sent through the login proxy.
// Requests without the mark use the direct connection even when a proxy is
// configured. The returned stats are shared by all contexts derived from ctx.
func WithLoginProxy(ctx context.Context) (context.Context, *LoginProxyStats) {
	stats := &LoginProxyStats{}
	return context.WithValue(ctx, loginProxyCtxKey{}, stats), stats
}

func loginProxyStatsFrom(r *http.Request) *LoginProxyStats {
	stats, _ := r.Context().Value(loginProxyCtxKey{}).(*LoginProxyStats)
	return stats
}

// loginProxyURL parses Config.LoginProxyURL. An empty value means no proxy.
// Error messages deliberately never echo the URL: it usually carries the
// proxy credentials.
func (config *Config) loginProxyURL() (*url.URL, error) {
	if config.LoginProxyURL == "" {
		return nil, nil
	}
	u, err := url.Parse(config.LoginProxyURL)
	if err != nil {
		return nil, errors.New("LoginProxyURL is not a valid URL")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("LoginProxyURL scheme %q is not supported (use http, https, socks5 or socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("LoginProxyURL has no host")
	}
	return u, nil
}

// loginProxyRouter sends marked requests through the proxied transport and
// everything else through the direct one. The two transports keep separate
// connection pools, so a proxied login never leaks a proxied connection into
// the Drive traffic that follows it.
type loginProxyRouter struct {
	direct  *http.Transport
	proxied *http.Transport
}

func newLoginProxyRouter(direct *http.Transport, proxyURL *url.URL) *loginProxyRouter {
	proxied := direct.Clone()
	proxied.Proxy = http.ProxyURL(proxyURL)
	return &loginProxyRouter{direct: direct, proxied: proxied}
}

func (t *loginProxyRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	stats := loginProxyStatsFrom(r)
	if stats == nil {
		return t.direct.RoundTrip(r)
	}
	atomic.AddInt64(&stats.Requests, 1)
	if r.ContentLength > 0 {
		atomic.AddInt64(&stats.Bytes, r.ContentLength)
	}
	resp, err := t.proxied.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &countingBody{ReadCloser: resp.Body, counter: &stats.Bytes}
	return resp, nil
}

// CloseIdleConnections lets http.Client.CloseIdleConnections (called from
// proton.Manager.Close) reach both connection pools.
func (t *loginProxyRouter) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.proxied.CloseIdleConnections()
}

type countingBody struct {
	io.ReadCloser
	counter *int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		atomic.AddInt64(b.counter, int64(n))
	}
	return n, err
}
