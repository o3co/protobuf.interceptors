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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// httpBackend is one of the endpoints that ask a backend over HTTP, with the
// body that backend answers an allow with.
type httpBackend struct {
	name  string
	build func(t *testing.T, baseURL string) VerifierEndpoint
	allow string
}

func httpBackends() []httpBackend {
	return []httpBackend{
		{
			name: "o3co",
			build: func(t *testing.T, baseURL string) VerifierEndpoint {
				t.Helper()
				ep, err := NewO3coEndpoint(baseURL)
				if err != nil {
					t.Fatalf("NewO3coEndpoint: %v", err)
				}
				return ep
			},
			allow: allowWithoutEvaluation,
		},
		{
			name: "opa",
			build: func(t *testing.T, baseURL string) VerifierEndpoint {
				t.Helper()
				ep, err := NewOPAEndpoint(baseURL, "authz/allow")
				if err != nil {
					t.Fatalf("NewOPAEndpoint: %v", err)
				}
				return ep
			},
			allow: `{"result": true}`,
		},
		{
			name: "cedar",
			build: func(t *testing.T, baseURL string) VerifierEndpoint {
				t.Helper()
				ep, err := NewCedarEndpoint(baseURL, WithCedarPrincipalResolver(tokenAsPrincipal))
				if err != nil {
					t.Fatalf("NewCedarEndpoint: %v", err)
				}
				return ep
			},
			allow: `{"decision": "Allow"}`,
		},
	}
}

// A redirect is not followed: the backend that was configured is the only one
// asked, and a 3xx from it is an error.
func TestHTTPEndpoints_DoNotFollowRedirects(t *testing.T) {
	for _, b := range httpBackends() {
		for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(b.name+"/"+http.StatusText(status), func(t *testing.T) {
				var reached atomic.Int32
				elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(b.allow))
				}))
				t.Cleanup(elsewhere.Close)
				redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, elsewhere.URL+r.URL.Path, status)
				}))
				t.Cleanup(redirecting.Close)

				err := b.build(t, redirecting.URL).Verify(ctxWithToken("tok"), "r", "a")
				var denied *interceptors.DeniedError
				if err == nil || errors.As(err, &denied) {
					t.Errorf("got %T: %v, want an error that is not a denial", err, err)
				}
				if n := reached.Load(); n != 0 {
					t.Errorf("the redirect target was asked %d times, want never", n)
				}
			})
		}
	}
}

// constructors builds each HTTP endpoint from a base URL, permitting plaintext
// to any host when allowInsecure is set.
var constructors = []struct {
	name  string
	build func(baseURL string, allowInsecure bool) error
}{
	{"o3co", func(baseURL string, allowInsecure bool) error {
		var opts []O3coOption
		if allowInsecure {
			opts = append(opts, WithO3coAllowInsecure())
		}
		_, err := NewO3coEndpoint(baseURL, opts...)
		return err
	}},
	{"opa", func(baseURL string, allowInsecure bool) error {
		var opts []OPAOption
		if allowInsecure {
			opts = append(opts, WithOPAAllowInsecure())
		}
		_, err := NewOPAEndpoint(baseURL, "authz/allow", opts...)
		return err
	}},
	{"cedar", func(baseURL string, allowInsecure bool) error {
		opts := []CedarOption{WithCedarPrincipalResolver(tokenAsPrincipal)}
		if allowInsecure {
			opts = append(opts, WithCedarAllowInsecure())
		}
		_, err := NewCedarEndpoint(baseURL, opts...)
		return err
	}},
}

// A base URL names its scheme, which is http or https, and a host. Nothing is
// guessed: a URL without a scheme is refused, not read as plaintext.
func TestHTTPEndpoints_RefuseABaseURLWithoutASchemeOrHost(t *testing.T) {
	for _, c := range constructors {
		for _, baseURL := range []string{
			"localhost:3000",
			"verifier.internal",
			"127.0.0.1:3000",
			"//verifier.internal",
			"ftp://localhost",
			"file:///etc/passwd",
			"unix:///var/run/verifier.sock",
			"http://",
			"https://",
			"https:///verify",
		} {
			for _, allowInsecure := range []bool{false, true} {
				t.Run(c.name+"/"+baseURL, func(t *testing.T) {
					if err := c.build(baseURL, allowInsecure); err == nil {
						t.Errorf("%q (allowInsecure=%v) was accepted", baseURL, allowInsecure)
					}
				})
			}
		}
	}
}

func TestHTTPEndpoints_AcceptHTTPSAndLoopbackPlaintext(t *testing.T) {
	for _, c := range constructors {
		for _, baseURL := range []string{
			"https://verifier.internal",
			"HTTPS://verifier.internal:8443/base",
			"http://localhost:3000",
			"http://LocalHost",
			"HTTP://127.0.0.1:8181",
			"http://127.1.2.3",
			"http://[::1]:3000",
		} {
			t.Run(c.name+"/"+baseURL, func(t *testing.T) {
				if err := c.build(baseURL, false); err != nil {
					t.Errorf("%q: unexpected error: %v", baseURL, err)
				}
			})
		}
	}
}

// Plaintext to a host other than this one carries the bearer token in the
// clear, so it takes an explicit option.
func TestHTTPEndpoints_RefusePlaintextToAnotherHostUnlessAllowed(t *testing.T) {
	for _, c := range constructors {
		for _, baseURL := range []string{
			"http://verifier.internal:3000",
			"http://10.0.0.1",
			"http://0.0.0.0:3000",
			"http://localhost.example.com",
			"http://[::2]",
		} {
			t.Run(c.name+"/"+baseURL, func(t *testing.T) {
				if err := c.build(baseURL, false); err == nil {
					t.Errorf("%q was accepted without the option", baseURL)
				}
				if err := c.build(baseURL, true); err != nil {
					t.Errorf("%q with the option: unexpected error: %v", baseURL, err)
				}
			})
		}
	}
}

// transported builds each HTTP endpoint over rt, with the given timeout.
var transported = []struct {
	name   string
	build  func(baseURL string, rt http.RoundTripper, timeout time.Duration) (VerifierEndpoint, error)
	allow  string
	nilOpt func()
}{
	{
		name: "o3co",
		build: func(baseURL string, rt http.RoundTripper, timeout time.Duration) (VerifierEndpoint, error) {
			return NewO3coEndpoint(baseURL, WithO3coTransport(rt), WithO3coTimeout(timeout))
		},
		allow:  allowWithoutEvaluation,
		nilOpt: func() { WithO3coTransport(nil) },
	},
	{
		name: "opa",
		build: func(baseURL string, rt http.RoundTripper, timeout time.Duration) (VerifierEndpoint, error) {
			return NewOPAEndpoint(baseURL, "authz/allow", WithOPATransport(rt), WithOPATimeout(timeout))
		},
		allow:  `{"result": true}`,
		nilOpt: func() { WithOPATransport(nil) },
	},
	{
		name: "cedar",
		build: func(baseURL string, rt http.RoundTripper, timeout time.Duration) (VerifierEndpoint, error) {
			return NewCedarEndpoint(baseURL, WithCedarPrincipalResolver(tokenAsPrincipal), WithCedarTransport(rt), WithCedarTimeout(timeout))
		},
		allow:  `{"decision": "Allow"}`,
		nilOpt: func() { WithCedarTransport(nil) },
	},
}

// countingTransport counts the requests it carries, and hands them to next.
type countingTransport struct {
	calls atomic.Int32
	next  http.RoundTripper
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.next.RoundTrip(req)
}

func TestHTTPEndpoints_Transport_CarriesTheRequests(t *testing.T) {
	for _, b := range transported {
		t.Run(b.name, func(t *testing.T) {
			rt := &countingTransport{next: http.DefaultTransport}
			ep, err := b.build(serve(t, http.StatusOK, b.allow).URL, rt, time.Second)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err := ep.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n := rt.calls.Load(); n != 1 {
				t.Errorf("the transport carried %d requests, want 1", n)
			}
		})
	}
}

// The endpoint, not the transport, decides that a redirect is not followed.
func TestHTTPEndpoints_Transport_DoesNotFollowRedirects(t *testing.T) {
	for _, b := range transported {
		t.Run(b.name, func(t *testing.T) {
			var reached atomic.Int32
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached.Add(1)
				_, _ = w.Write([]byte(b.allow))
			}))
			t.Cleanup(elsewhere.Close)
			redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(redirecting.Close)

			rt := &countingTransport{next: http.DefaultTransport}
			ep, err := b.build(redirecting.URL, rt, time.Second)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err := ep.Verify(ctxWithToken("tok"), "r", "a"); err == nil {
				t.Error("expected an error for a redirect")
			}
			if n := reached.Load(); n != 0 {
				t.Errorf("the redirect target was asked %d times, want never", n)
			}
			if n := rt.calls.Load(); n != 1 {
				t.Errorf("the transport carried %d requests, want 1", n)
			}
		})
	}
}

// stallingTransport answers nothing until the request is abandoned, and
// records that it was entered and why the request ended.
type stallingTransport struct {
	entered atomic.Int32
	ended   chan error
}

func (s *stallingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.entered.Add(1)
	<-req.Context().Done()
	s.ended <- req.Context().Err()
	return nil, req.Context().Err()
}

// The endpoint's timeout bounds a request over a transport of the caller's:
// the request reaches the transport, and the timeout is what ends it.
func TestHTTPEndpoints_Transport_KeepsTheTimeout(t *testing.T) {
	const timeout = 50 * time.Millisecond
	for _, b := range transported {
		t.Run(b.name, func(t *testing.T) {
			rt := &stallingTransport{ended: make(chan error, 1)}
			ep, err := b.build("http://localhost:1", rt, timeout)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			done := make(chan error, 1)
			start := time.Now()
			go func() { done <- ep.Verify(ctxWithToken("tok"), "r", "a") }()
			select {
			case err := <-done:
				if err == nil {
					t.Error("expected an error for a request that timed out")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the timeout was not enforced")
			}
			if elapsed := time.Since(start); elapsed < timeout {
				t.Errorf("the call ended after %v, before the %v timeout", elapsed, timeout)
			}
			if n := rt.entered.Load(); n != 1 {
				t.Fatalf("the transport was entered %d times, want 1", n)
			}
			if cause := <-rt.ended; !errors.Is(cause, context.DeadlineExceeded) {
				t.Errorf("the request ended with %v, want its deadline", cause)
			}
		})
	}
}

func TestHTTPEndpoints_NilTransport_Panics(t *testing.T) {
	for _, b := range transported {
		t.Run(b.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected a panic for a nil transport")
				}
			}()
			b.nilOpt()
		})
	}
}

// bufferLogger returns a logger at level writing to the buffer it returns.
func bufferLogger(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})), &buf
}

// An error answer is logged at the default level by its status and request
// ID; its body, which may echo the request, only at Debug.
func TestOPAAndCedar_ErrorResponseBody_IsLoggedOnlyAtDebug(t *testing.T) {
	const body = `{"error": "leak-me"}`
	setLogger := map[string]func(VerifierEndpoint, *slog.Logger){
		"opa":   func(ep VerifierEndpoint, l *slog.Logger) { ep.(*opaEndpoint).logger = l },
		"cedar": func(ep VerifierEndpoint, l *slog.Logger) { ep.(*cedarEndpoint).logger = l },
	}
	for _, b := range httpBackends() {
		set, ok := setLogger[b.name]
		if !ok {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			ep := b.build(t, serve(t, http.StatusInternalServerError, body).URL)

			logger, logs := bufferLogger(slog.LevelError)
			set(ep, logger)
			_ = ep.Verify(ctxWithTokenAndRequestID("tok", "req-1"), "r", "a")
			out := logs.String()
			if strings.Contains(out, "leak-me") {
				t.Errorf("default-level log carries the response body:\n%s", out)
			}
			for _, want := range []string{"level=ERROR", "status=500", "req-1"} {
				if !strings.Contains(out, want) {
					t.Errorf("default-level log lacks %q:\n%s", want, out)
				}
			}

			logger, logs = bufferLogger(slog.LevelDebug)
			set(ep, logger)
			_ = ep.Verify(ctxWithTokenAndRequestID("tok", "req-1"), "r", "a")
			if out := logs.String(); !strings.Contains(out, "leak-me") {
				t.Errorf("debug-level log lacks the response body:\n%s", out)
			}
		})
	}
}

var requestIDHeaderKeyOptions = map[string]func(key string){
	"o3co":  func(key string) { WithO3coRequestIDHeaderKey(key) },
	"opa":   func(key string) { WithOPARequestIDHeaderKey(key) },
	"cedar": func(key string) { WithCedarRequestIDHeaderKey(key) },
}

// The request-ID header is an RFC 7230 token, and not one of the headers the
// endpoint sets from its own state.
func TestRequestIDHeaderKey_ThatIsNotATokenOrIsControlled_Panics(t *testing.T) {
	for name, option := range requestIDHeaderKeyOptions {
		for _, key := range []string{"bad header", "x-request-id\r\nx-injected", "x:id", "Authorization", "authorization", "Content-Type", "ACCEPT"} {
			t.Run(name+"/"+key, func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Errorf("expected a panic for request-ID header %q", key)
					}
				}()
				option(key)
			})
		}
	}
}

func TestRequestIDHeaderKey_TokenOrEmpty_IsAccepted(t *testing.T) {
	for name, option := range requestIDHeaderKeyOptions {
		for _, key := range []string{"", "x-request-id", "X-Correlation-ID", "traceparent"} {
			t.Run(name+"/"+key, func(t *testing.T) {
				option(key)
			})
		}
	}
}

// stall answers nothing until the request is abandoned, after first writing
// prefix as the start of a 200 body when it is not empty.
func stall(t *testing.T, prefix string) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server notices the client leave only once the request body
		// is read.
		_, _ = io.Copy(io.Discard, r.Body)
		if prefix != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(prefix))
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

// When the caller's context ends, the error says so: errors.Is finds
// context.Canceled or context.DeadlineExceeded, wherever the request was.
func TestHTTPEndpoints_CallerContextEnded_WrapsItsError(t *testing.T) {
	for _, b := range httpBackends() {
		t.Run(b.name+"/cancelled before the request", func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctxWithToken("tok"))
			cancel()
			err := b.build(t, serve(t, http.StatusOK, b.allow).URL).Verify(ctx, "r", "a")
			if !errors.Is(err, context.Canceled) {
				t.Errorf("got %T: %v, want an error wrapping context.Canceled", err, err)
			}
		})
		t.Run(b.name+"/deadline while awaiting the answer", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctxWithToken("tok"), 50*time.Millisecond)
			defer cancel()
			err := b.build(t, stall(t, "").URL).Verify(ctx, "r", "a")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("got %T: %v, want an error wrapping context.DeadlineExceeded", err, err)
			}
		})
		t.Run(b.name+"/deadline while reading the body", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctxWithToken("tok"), 50*time.Millisecond)
			defer cancel()
			err := b.build(t, stall(t, b.allow[:5]).URL).Verify(ctx, "r", "a")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("got %T: %v, want an error wrapping context.DeadlineExceeded", err, err)
			}
		})
	}
}

// The endpoint's own timeout is the backend failing to answer, not the
// caller's deadline: the error wraps no context error.
func TestHTTPEndpoints_EndpointTimeout_IsNotTheCallersContext(t *testing.T) {
	for _, b := range transported {
		for name, prefix := range map[string]string{"awaiting the answer": "", "reading the body": b.allow[:5]} {
			t.Run(b.name+"/"+name, func(t *testing.T) {
				ep, err := b.build(stall(t, prefix).URL, http.DefaultTransport, 50*time.Millisecond)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = ep.Verify(ctxWithToken("tok"), "r", "a")
				if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					t.Errorf("got %T: %v, want an error wrapping no context error", err, err)
				}
			})
		}
	}
}

// A body past the size bound is not read as a decision, even when the part
// within it is an allow.
func TestOPAAndCedar_OversizedAllow_IsAnError(t *testing.T) {
	const opaAllow, cedarAllow = `{"result": true}`, `{"decision": "Allow"}`
	cases := map[string]func(url string) (VerifierEndpoint, error){
		"opa": func(url string) (VerifierEndpoint, error) {
			return NewOPAEndpoint(url, "authz/allow", WithOPAMaxResponseBodySize(int64(len(opaAllow))))
		},
		"cedar": func(url string) (VerifierEndpoint, error) {
			return NewCedarEndpoint(url, WithCedarPrincipalResolver(tokenAsPrincipal), WithCedarMaxResponseBodySize(int64(len(cedarAllow))))
		},
	}
	bodies := map[string]string{"opa": opaAllow, "cedar": cedarAllow}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			ep, err := build(serve(t, http.StatusOK, bodies[name]+"          ").URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			err = ep.Verify(ctxWithToken("tok"), "r", "a")
			var denied *interceptors.DeniedError
			if err == nil || errors.As(err, &denied) {
				t.Errorf("got %T: %v, want an error that is not a denial", err, err)
			}

			// At the bound exactly, the body is read.
			ep, _ = build(serve(t, http.StatusOK, bodies[name]).URL)
			if err := ep.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
				t.Errorf("a body at the bound: unexpected error: %v", err)
			}
		})
	}
}

// A base URL's password stays out of the error, whatever is wrong with it.
func TestHTTPEndpoints_BaseURLError_DoesNotCarryThePassword(t *testing.T) {
	for _, c := range constructors {
		for _, baseURL := range []string{
			"https://svc:s3cret@verifier internal/",
			"https://svc:s3cret@verifier.internal:port/",
			"http://svc:s3cret@verifier.internal/",
			"ftp://svc:s3cret@verifier.internal/",
		} {
			t.Run(c.name+"/"+baseURL, func(t *testing.T) {
				err := c.build(baseURL, false)
				if err == nil {
					t.Fatalf("%q was accepted", baseURL)
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Errorf("the error carries the password: %v", err)
				}
			})
		}
	}
}

// Loopback is localhost by name, in any case, or a literal address in
// 127.0.0.0/8 or ::1 — not a name or spelling that some resolver or parser
// might also take to be one.
func TestHTTPEndpoints_LoopbackEdges(t *testing.T) {
	accepted := []string{"LOCALHOST", "[::ffff:127.0.0.1]", "[0:0:0:0:0:0:0:1]", "127.255.255.254"}
	refused := []string{"localhost.", "127.1", "0.0.0.0", "[::1%25lo0]", "[fe80::1%25en0]", "2130706433", "0x7f.1", "foo.localhost"}
	for _, c := range constructors {
		for _, host := range accepted {
			t.Run(c.name+"/accepted/"+host, func(t *testing.T) {
				if err := c.build("http://"+host+":3000", false); err != nil {
					t.Errorf("http://%s: unexpected error: %v", host, err)
				}
			})
		}
		for _, host := range refused {
			t.Run(c.name+"/refused/"+host, func(t *testing.T) {
				if err := c.build("http://"+host+":3000", false); err == nil {
					t.Errorf("http://%s was accepted as loopback", host)
				}
			})
		}
	}
}
