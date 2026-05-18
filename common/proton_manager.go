package common

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/henrybear327/go-proton-api"
)

func getProtonManager(appVersion string, userAgent string) *proton.Manager {
	/* Notes on API calls: if the app version is not specified, the api calls will be rejected. */
	// ForceAttemptHTTP2 is required: setting DialContext or TLSClientConfig
	// causes Go's http.Transport to conservatively disable HTTP/2. Without
	// this flag the connection falls back to HTTP/1.1, which Proton's
	// anti-abuse system treats as a non-official client and rejects with
	// 422 Code=2028 on /auth/v4.
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		ExpectContinueTimeout: 1 * time.Second,
	}

	options := []proton.Option{
		proton.WithAppVersion(appVersion),
		proton.WithUserAgent(userAgent),
		proton.WithTransport(transport),
	}
	m := proton.New(options...)

	return m
}
