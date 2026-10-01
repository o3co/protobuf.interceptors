// Copyright 2026 1o1 Co. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// parseBaseURL parses the URL an endpoint asks its backend at. It must name
// http or https and a host. Every request carries the subject's bearer token,
// so plaintext is refused unless the host is loopback or allowInsecure is set;
// insecureOption names the option that sets it.
func parseBaseURL(raw string, allowInsecure bool, insecureOption string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("baseURL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("base URL must name the scheme http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("base URL must name a host")
	}
	if u.Scheme == "http" && !allowInsecure && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("base URL %s sends the bearer token in plaintext to a host other than loopback: use https, or %s to permit it", u.Redacted(), insecureOption)
	}
	return u, nil
}

// isLoopback reports whether host is localhost, or an address in 127.0.0.0/8
// or ::1.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// maxLoggedBodySize bounds how much of a response body is logged, at Debug.
const maxLoggedBodySize = 1024

// truncatedBody returns body cut to maxLoggedBodySize, for a Debug log line.
// A body is never logged at the default level: it may echo the request or
// carry the reasons behind a decision.
func truncatedBody(body []byte) string {
	if len(body) > maxLoggedBodySize {
		body = body[:maxLoggedBodySize]
	}
	return string(body)
}

// newHTTPClient returns the client an endpoint asks its backend with, over
// transport, or http.DefaultTransport when it is nil. It follows no redirect,
// whatever the transport: a 3xx is the answer, which every endpoint reads as
// an error, so the request and the credentials on it reach only the
// configured backend.
func newHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
