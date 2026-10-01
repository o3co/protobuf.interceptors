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
	"context"
	"errors"
	"fmt"
	"io"
	"math"
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
		// A *url.Error quotes the whole URL, password included; its cause
		// names only what is wrong.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
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

// isLoopback reports whether host is localhost, in any case, or a literal
// address in 127.0.0.0/8 or ::1. localhost is taken by name, and resolves
// like any other host; a shorthand, numeric or zoned spelling of an address
// is not loopback.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// endpointControlledHeaders are the headers an endpoint sets from its own
// state, which neither the request-ID header nor a static header may name.
var endpointControlledHeaders = []string{"Content-Type", "Accept", "Authorization"}

// mustBeRequestIDHeaderKey panics unless key is empty, which disables
// forwarding, or an RFC 7230 token that is not one of
// endpointControlledHeaders: a request ID sent under Authorization would
// replace the bearer token.
func mustBeRequestIDHeaderKey(key string) {
	if key == "" {
		return
	}
	if !validHeaderName(key) {
		panic(fmt.Sprintf("request-ID header key %q is not an RFC 7230 token", key))
	}
	for _, name := range endpointControlledHeaders {
		if strings.EqualFold(key, name) {
			panic(fmt.Sprintf("request-ID header key %q is set by the endpoint", key))
		}
	}
}

// validHeaderName reports whether name is a non-empty RFC 7230 field-name.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// requestError reports err, which ended a request to the backend made under
// ctx. When ctx itself ended, the error wraps ctx.Err(), so errors.Is finds
// context.Canceled or context.DeadlineExceeded. Otherwise it is the backend's
// failure and wraps no context error — net/http reports the endpoint's own
// timeout as context.DeadlineExceeded, which must not read as the caller's.
func requestError(ctx context.Context, what string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%s: %w", what, ctxErr)
	}
	return fmt.Errorf("%s: %v", what, err)
}

// readBounded reads body up to max bytes, and reports whether it held more.
// It reads one byte past max to tell a body at the bound from one past it:
// a body cut at the bound is not read as a decision, since the part of it
// within the bound can be one.
func readBounded(body io.Reader, max int64) (data []byte, oversized bool, err error) {
	limit := max
	if limit < math.MaxInt64 {
		limit++
	}
	data, err = io.ReadAll(io.LimitReader(body, limit))
	if int64(len(data)) > max {
		return data[:max], true, err
	}
	return data, false, err
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
// transport, or http.DefaultTransport when it is nil. The client follows no
// redirect: a 3xx is the answer, which every endpoint reads as an error, so
// the request and the credentials on it reach only the configured backend.
// Its timeout ends a request by cancelling the request's context. Both hold
// for a transport that honours that context and does not follow redirects
// itself, as *http.Transport does; a transport of the caller's that does
// neither is outside what the client can enforce.
func newHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
