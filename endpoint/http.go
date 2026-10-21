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
	"net/netip"
	"net/url"
	"strings"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/internal/privatenet"
)

// reachConfig is what an HTTP endpoint's options say about how its backend is
// reached: over which transport, and to which hosts in plaintext.
type reachConfig struct {
	allowInsecure bool
	// plainInternal holds the listed host:port pairs, each as
	// plainInternalPair spells it.
	plainInternal map[string]struct{}
	transport     http.RoundTripper
	// privateDialer resolves and connects for a listed pair. Its zero value
	// uses the system resolver and a net.Dialer.
	privateDialer privatenet.Dialer
}

// addPlainInternal lists pairs, each already spelled by plainInternalPair.
func (r *reachConfig) addPlainInternal(pairs []string) {
	if r.plainInternal == nil {
		r.plainInternal = make(map[string]struct{}, len(pairs))
	}
	for _, pair := range pairs {
		r.plainInternal[pair] = struct{}{}
	}
}

// client parses raw, the URL an endpoint asks its backend at, and returns it
// with the client that asks it. kind names the endpoint's options:
// With{kind}AllowInsecure, With{kind}AllowPlainInternal, With{kind}Transport.
//
// Every request carries the subject's bearer token or what was resolved from
// it, so plaintext is refused unless the host is loopback, the host and port
// are listed with With{kind}AllowPlainInternal, or With{kind}AllowInsecure is
// given. A listed pair is reached over the endpoint's own transport, which
// connects only when every address the host resolves to is private and uses
// no proxy. That holds under With{kind}AllowInsecure too, and a listed pair
// is refused over a caller's transport, which the check would not run in.
func (r *reachConfig) client(raw string, timeout time.Duration, kind string) (*url.URL, *http.Client, error) {
	u, err := parseBaseURL(raw)
	if err != nil {
		return nil, nil, err
	}
	transport := r.transport
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		listed := false
		if pair, ok := urlPair(u); ok {
			_, listed = r.plainInternal[pair]
		}
		switch {
		case listed && r.transport != nil:
			return nil, nil, fmt.Errorf("base URL %s is listed with With%sAllowPlainInternal, whose address check runs in the endpoint's own transport: it cannot be reached over With%sTransport", u.Redacted(), kind, kind)
		case listed:
			dialer := r.privateDialer
			dialer.Timeout = timeout
			transport = privateTransport(&dialer)
		case !r.allowInsecure:
			return nil, nil, fmt.Errorf("base URL %s sends the bearer token in plaintext to a host other than loopback: use https, list its host and port with With%sAllowPlainInternal for a host on a private network, or permit it with With%sAllowInsecure", u.Redacted(), kind, kind)
		}
	}
	return u, newHTTPClient(timeout, transport), nil
}

// parseBaseURL parses the URL an endpoint asks its backend at. It must name
// http or https and a host.
func parseBaseURL(raw string) (*url.URL, error) {
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
	return u, nil
}

// plainInternalPair returns entry, a host and port, spelled the one way a
// base URL's are compared with it: a name in lower case without one trailing
// dot, an address in its canonical form, an IPv4 address mapped into IPv6 as
// the IPv4 address, and the port as written. It refuses an entry that is not
// a host and port, whose port is not a decimal from 1 to 65535 without a
// leading zero, whose name is not a host name (see validHostName), or whose
// address is not on a private network: such an entry is never reached.
func plainInternalPair(entry string) (string, error) {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		return "", fmt.Errorf("plain-internal entry %q is not a host and port: %w", entry, err)
	}
	if !validPort(port) {
		return "", fmt.Errorf("plain-internal entry %q: the port must be a number from 1 to 65535, written without a leading zero", entry)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !privatenet.Contains(addr) {
			return "", fmt.Errorf("plain-internal entry %q: the address is not on a private network", entry)
		}
		return net.JoinHostPort(addr.Unmap().String(), port), nil
	}
	name, ascii := asciiLower(strings.TrimSuffix(host, "."))
	if !ascii || !validHostName(name) {
		return "", fmt.Errorf("plain-internal entry %q: the host is neither an address nor a host name", entry)
	}
	return net.JoinHostPort(name, port), nil
}

// urlPair returns u's host and port spelled as plainInternalPair spells an
// entry; a URL without a port has http's. It reports false for a host that
// no entry can name: an address privatenet.Contains refuses, a zoned one
// included, a name that is not ASCII, since net/http asks for its IDNA form
// and case folding could make it read as an entry, and a name that
// validHostName refuses, such as an address with a trailing dot.
func urlPair(u *url.URL) (string, bool) {
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if !privatenet.Contains(addr) {
			return "", false
		}
		host = addr.Unmap().String()
	} else {
		var ascii bool
		if host, ascii = asciiLower(strings.TrimSuffix(host, ".")); !ascii || !validHostName(host) {
			return "", false
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(host, port), true
}

// asciiLower returns s with its ASCII letters in lower case, and reports
// whether s is all ASCII.
func asciiLower(s string) (string, bool) {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 0x80:
			return "", false
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b), true
}

// validPort reports whether port is a decimal from 1 to 65535 with no
// leading zero.
func validPort(port string) bool {
	if port == "" || len(port) > 5 || port[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n <= 65535
}

// validHostName reports whether name, in lower case, is a host name: labels
// of 1 to 63 letters, digits, hyphens and underscores, none starting or
// ending with a hyphen, at most 253 in all, the last not all digits, which a
// resolver may read as an address. The underscore, outside RFC 1123, is in
// service names container networks resolve, and Go's resolver takes it.
func validHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// privateTransport returns the transport a listed pair is reached over: it
// connects through d, and uses no proxy, since a proxy would carry the
// request on in plaintext and resolve the host itself. Each endpoint has its
// own, and so its own pool of idle connections.
func privateTransport(d *privatenet.Dialer) *http.Transport {
	return &http.Transport{
		DialContext:           d.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
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
// ctx before its answer was whole. When ctx itself ended, the error wraps
// ctx.Err(), so errors.Is finds context.Canceled or context.DeadlineExceeded.
// Otherwise the backend could not be reached, did not answer within the
// endpoint's own timeout, or broke the connection, and the error wraps
// interceptors.ErrBackendUnavailable and no context error — net/http reports
// the endpoint's own timeout as context.DeadlineExceeded, which must not read
// as the caller's. A host the private-network check refused is this
// service's refusal, not the backend's failure, and wraps neither.
func requestError(ctx context.Context, what string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%s: %w", what, ctxErr)
	}
	if errors.Is(err, privatenet.ErrNotPrivate) {
		return fmt.Errorf("%s: %v", what, err)
	}
	return fmt.Errorf("%w: %s: %v", interceptors.ErrBackendUnavailable, what, err)
}

// statusError returns err, which reports a status the endpoint does not take
// as an answer, wrapping interceptors.ErrBackendUnavailable when the status
// says the backend is overloaded or down: 429, 502, 503 or 504, the statuses
// gRPC's and Connect's HTTP mappings read as unavailable. Any other status,
// 500 and 3xx included, says the backend or this service is misconfigured or
// broke the contract.
func statusError(status int, err error) error {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("%w: %v", interceptors.ErrBackendUnavailable, err)
	}
	return err
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

// mustBePlainInternalPairs returns entries each spelled by plainInternalPair,
// and panics on the first it refuses.
func mustBePlainInternalPairs(entries []string) []string {
	pairs := make([]string, len(entries))
	for i, entry := range entries {
		pair, err := plainInternalPair(entry)
		if err != nil {
			panic(err.Error())
		}
		pairs[i] = pair
	}
	return pairs
}
