package common

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// proton.Manager.Close relies on http.Client.CloseIdleConnections reaching the transport.
var _ interface{ CloseIdleConnections() } = (*loginProxyRouter)(nil)

func TestLoginProxyRouterRoutesOnlyMarkedRequests(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		// An HTTP proxy receives the absolute-form request line, so the
		// original target must show up as the URL host.
		if r.URL.Host != targetHost {
			t.Errorf("proxy got request for host %q, want %q", r.URL.Host, targetHost)
		}
		_, _ = io.WriteString(w, "via-proxy")
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: newLoginProxyRouter(&http.Transport{}, proxyURL)}

	body := func(req *http.Request) string {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// Unmarked request: direct, no stats.
	plain, _ := http.NewRequest(http.MethodGet, target.URL+"/drive/volumes", nil)
	if got := body(plain); got != "direct" {
		t.Fatalf("unmarked request body = %q, want direct", got)
	}
	if n := atomic.LoadInt32(&proxyHits); n != 0 {
		t.Fatalf("unmarked request reached the proxy %d times", n)
	}

	// Marked request: through the proxy, counted.
	ctx, stats := WithLoginProxy(context.Background())
	marked, _ := http.NewRequestWithContext(ctx, http.MethodPost, target.URL+"/auth/v4", strings.NewReader("hello"))
	if got := body(marked); got != "via-proxy" {
		t.Fatalf("marked request body = %q, want via-proxy", got)
	}
	if n := atomic.LoadInt32(&proxyHits); n != 1 {
		t.Fatalf("marked request reached the proxy %d times, want 1", n)
	}
	if stats.Requests != 1 {
		t.Fatalf("stats.Requests = %d, want 1", stats.Requests)
	}
	if want := int64(len("hello") + len("via-proxy")); stats.Bytes != want {
		t.Fatalf("stats.Bytes = %d, want %d", stats.Bytes, want)
	}

	// A context derived from the marked one shares the same stats.
	derived, _ := http.NewRequestWithContext(context.WithValue(ctx, struct{}{}, 0), http.MethodGet, target.URL+"/core/v4/users", nil)
	if got := body(derived); got != "via-proxy" {
		t.Fatalf("derived-context request body = %q, want via-proxy", got)
	}
	if stats.Requests != 2 {
		t.Fatalf("stats.Requests after derived request = %d, want 2", stats.Requests)
	}

	// Unmarked again after proxied traffic: still direct.
	if got := body(plain.Clone(context.Background())); got != "direct" {
		t.Fatalf("second unmarked request body = %q, want direct", got)
	}
}

func TestConfigLoginProxyURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr string // substring; empty means no error
		wantNil bool
	}{
		{name: "empty means no proxy", raw: "", wantNil: true},
		{name: "http with credentials", raw: "http://user-session-abc:secret@proxy.example.com:8080"},
		{name: "socks5", raw: "socks5://proxy.example.com:1080"},
		{name: "unsupported scheme", raw: "ftp://secret@proxy.example.com", wantErr: "scheme"},
		{name: "missing host", raw: "http://", wantErr: "no host"},
		{name: "unparsable", raw: "://secret", wantErr: "not a valid URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewConfigWithDefaultValues()
			config.LoginProxyURL = tc.raw
			u, err := config.loginProxyURL()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				// Never leak proxy credentials through error messages.
				if strings.Contains(err.Error(), "secret") {
					t.Fatalf("error message leaks the URL: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil {
				if u != nil {
					t.Fatalf("got %v, want nil", u)
				}
				return
			}
			if u == nil || u.String() != tc.raw {
				t.Fatalf("got %v, want %q", u, tc.raw)
			}
		})
	}
}
