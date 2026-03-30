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
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,
		ExpectContinueTimeout:  1 * time.Second,
	}

	options := []proton.Option{
		proton.WithAppVersion(appVersion),
		proton.WithUserAgent(userAgent),
		proton.WithTransport(transport),
	}
	m := proton.New(options...)

	return m
}
