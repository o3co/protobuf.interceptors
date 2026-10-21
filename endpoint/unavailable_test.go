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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/internal/privatenet"
)

// assertUnavailable fails unless err refuses and wraps
// interceptors.ErrBackendUnavailable, and no context error.
func assertUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, interceptors.ErrBackendUnavailable) {
		t.Errorf("got %T: %v, want an error wrapping ErrBackendUnavailable", err, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want an error wrapping no context error", err)
	}
	var denied *interceptors.DeniedError
	if errors.As(err, &denied) {
		t.Errorf("got a denial %v, want a failure", err)
	}
}

// assertNotUnavailable fails unless err is an error that does not wrap
// interceptors.ErrBackendUnavailable.
func assertNotUnavailable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("got no error")
	}
	if errors.Is(err, interceptors.ErrBackendUnavailable) {
		t.Errorf("got %v, want an error that does not wrap ErrBackendUnavailable", err)
	}
}

// A backend that answers it is overloaded or down — the statuses gRPC's and
// Connect's HTTP mappings read as unavailable — is unavailable, whatever the
// body holds.
func TestHTTPEndpoints_OverloadedOrDownStatus_IsUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
			t.Run(b.name+"/"+http.StatusText(status), func(t *testing.T) {
				for _, body := range []string{"", b.allow, "not json"} {
					assertUnavailable(t, b.build(t, serve(t, status, body).URL).Verify(ctxWithToken("tok"), "r", "a"))
				}
			})
		}
	}
}

// The verifier's own refusal when it cannot verify the credential now is a
// 503 with the code verification_unavailable: unavailable.
func TestO3co_VerificationUnavailable_IsUnavailable(t *testing.T) {
	srv := serve(t, http.StatusServiceUnavailable, `{"error":"Service Unavailable","code":"verification_unavailable","message":"keys could not be fetched"}`)
	_, err := newTestEndpoint(t, srv.URL).VerifyDecision(ctxWithToken("tok"), "r", "a")
	assertUnavailable(t, err)
}

// Every other answer that is not an allow or a refusal of the subject says
// the backend or this service is misconfigured or broke the contract: it is
// not unavailable.
func TestHTTPEndpoints_OtherFailures_AreNotUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		for _, status := range []int{
			http.StatusInternalServerError, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported,
			http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge,
			http.StatusFound, http.StatusNotModified,
		} {
			t.Run(b.name+"/"+http.StatusText(status), func(t *testing.T) {
				assertNotUnavailable(t, b.build(t, serve(t, status, "").URL).Verify(ctxWithToken("tok"), "r", "a"))
			})
		}
		t.Run(b.name+"/malformed body", func(t *testing.T) {
			assertNotUnavailable(t, b.build(t, serve(t, http.StatusOK, "not json").URL).Verify(ctxWithToken("tok"), "r", "a"))
		})
	}
	t.Run("o3co/caller unauthenticated", func(t *testing.T) {
		srv := serve(t, http.StatusUnauthorized, `{"error":"Unauthorized","code":"caller_unauthenticated","message":"no"}`)
		assertNotUnavailable(t, newTestEndpoint(t, srv.URL).Verify(ctxWithToken("tok"), "r", "a"))
	})
	t.Run("o3co/201", func(t *testing.T) {
		srv := serve(t, http.StatusCreated, allowWithoutEvaluation)
		assertNotUnavailable(t, newTestEndpoint(t, srv.URL).Verify(ctxWithToken("tok"), "r", "a"))
	})
}

// A backend that cannot be connected to is unavailable.
func TestHTTPEndpoints_ConnectionRefused_IsUnavailable(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	for _, b := range httpBackends() {
		t.Run(b.name, func(t *testing.T) {
			assertUnavailable(t, b.build(t, "http://"+addr).Verify(ctxWithToken("tok"), "r", "a"))
		})
	}
}

// The endpoint's own timeout, while the caller's context is live, is the
// backend failing to answer in time: unavailable, wherever it fired.
func TestHTTPEndpoints_EndpointTimeout_IsUnavailable(t *testing.T) {
	for _, b := range transported {
		for name, prefix := range map[string]string{"awaiting the answer": "", "reading the body": b.allow[:5]} {
			t.Run(b.name+"/"+name, func(t *testing.T) {
				ep, err := b.build(stall(t, prefix).URL, http.DefaultTransport, 50*time.Millisecond)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				assertUnavailable(t, ep.Verify(ctxWithToken("tok"), "r", "a"))
			})
		}
	}
}

// A connection that breaks after a 200 and before its body is whole is a
// transport failure: unavailable, never an allow.
func TestHTTPEndpoints_ConnectionBrokenWhileReadingTheBody_IsUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		t.Run(b.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n" + b.allow)
				_ = buf.Flush()
			}))
			t.Cleanup(srv.Close)
			assertUnavailable(t, b.build(t, srv.URL).Verify(ctxWithToken("tok"), "r", "a"))
		})
	}
}

// When the caller's context ends, the error is the caller's, not the
// backend's: it does not wrap ErrBackendUnavailable.
func TestHTTPEndpoints_CallerContextEnded_IsNotUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		t.Run(b.name+"/awaiting the answer", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctxWithToken("tok"), 50*time.Millisecond)
			defer cancel()
			err := b.build(t, stall(t, "").URL).Verify(ctx, "r", "a")
			assertNotUnavailable(t, err)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("got %v, want an error wrapping context.DeadlineExceeded", err)
			}
		})
		t.Run(b.name+"/reading the body", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctxWithToken("tok"), 50*time.Millisecond)
			defer cancel()
			err := b.build(t, stall(t, b.allow[:5]).URL).Verify(ctx, "r", "a")
			assertNotUnavailable(t, err)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("got %v, want an error wrapping context.DeadlineExceeded", err)
			}
		})
	}
}

// A failure that comes from configuration or from what the backend sent, not
// from reaching it, is not unavailable: retrying does not fix it.
func TestHTTPEndpoints_DeterministicTransportFailures_AreNotUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		t.Run(b.name+"/a certificate this side does not trust", func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(b.allow))
			}))
			t.Cleanup(srv.Close)
			assertNotUnavailable(t, b.build(t, srv.URL).Verify(ctxWithToken("tok"), "r", "a"))
		})
		t.Run(b.name+"/a certificate that does not parse", func(t *testing.T) {
			assertNotUnavailable(t, b.build(t, "https://"+malformedCertificateServer(t)).Verify(ctxWithToken("tok"), "r", "a"))
		})
		t.Run(b.name+"/https to a backend that speaks http", func(t *testing.T) {
			srv := serve(t, http.StatusOK, b.allow)
			assertNotUnavailable(t, b.build(t, "https://"+srv.Listener.Addr().String()).Verify(ctxWithToken("tok"), "r", "a"))
		})
		// The endpoints ask for no content coding, so a coded body is read
		// as it came, never decoded, and a decoder's error is never mistaken
		// for a broken connection.
		for name, body := range map[string]string{
			"a body that does not decode": "this is not gzip at all, and long enough to read a header from",
			"a gzip body cut short":       "\x1f",
		} {
			t.Run(b.name+"/"+name, func(t *testing.T) {
				var acceptEncoding string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					acceptEncoding = r.Header.Get("Accept-Encoding")
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte(body))
				}))
				t.Cleanup(srv.Close)
				assertNotUnavailable(t, b.build(t, srv.URL).Verify(ctxWithToken("tok"), "r", "a"))
				if acceptEncoding != "identity" {
					t.Errorf("Accept-Encoding = %q, want identity", acceptEncoding)
				}
			})
		}
		t.Run(b.name+"/a port no address can have", func(t *testing.T) {
			assertNotUnavailable(t, b.build(t, "http://127.0.0.1:65536").Verify(ctxWithToken("tok"), "r", "a"))
		})
	}
}

// A host whose name does not resolve cannot be told from a resolver that is
// down: unavailable.
func TestHTTPEndpoints_LookupFailure_IsUnavailable(t *testing.T) {
	for _, b := range httpBackends() {
		t.Run(b.name, func(t *testing.T) {
			assertUnavailable(t, b.build(t, "https://pdp.invalid").Verify(ctxWithToken("tok"), "r", "a"))
		})
	}
}

// Every failure to send a request or read its answer is transient but the
// ones that come from configuration or from what was sent, which retrying
// does not change.
func TestTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"a connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, true},
		{"a connection reset", &url.Error{Op: "Post", URL: "u", Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}, true},
		{"a failed lookup", &net.DNSError{Err: "no such host", Name: "pdp", IsNotFound: true}, true},
		{"a connection closed before the answer", &url.Error{Op: "Post", URL: "u", Err: io.EOF}, true},
		{"a body cut off", io.ErrUnexpectedEOF, true},
		{"a timeout", &url.Error{Op: "Post", URL: "u", Err: timeoutError{}}, true},
		// net/http's HTTP/2 errors, a GOAWAY among them, are of types it
		// does not export: a failure this library cannot name is the
		// backend's.
		{"a failure this library cannot name", &url.Error{Op: "Post", URL: "u", Err: errors.New("http2: server sent GOAWAY and closed the connection")}, true},
		{"a TLS alert the backend sent", &url.Error{Op: "Post", URL: "u", Err: &net.OpError{Op: "remote error", Err: tls.AlertError(42)}}, false},
		{"a TLS alert this side sent", &url.Error{Op: "Post", URL: "u", Err: fmt.Errorf("tls: bad certificate%.0w", tls.AlertError(42))}, false},
		{"a certificate this side refuses", &url.Error{Op: "Post", URL: "u", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}, false},
		{"a backend that does not speak TLS", &url.Error{Op: "Post", URL: "u", Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}, false},
		{"crypto/tls refusing the handshake", &url.Error{Op: "Post", URL: "u", Err: errors.New("tls: failed to parse certificate from server: x509: malformed certificate")}, false},
		{"crypto/tls refusing, beside another error", &url.Error{Op: "Post", URL: "u", Err: fmt.Errorf("transport: %w; cleanup: %w", errors.New("tls: failed to parse certificate from server"), io.EOF)}, false},
		{"crypto/tls refusing, joined", errors.Join(io.EOF, errors.New("tls: failed to parse certificate from server")), false},
		{"a scheme mismatch", &url.Error{Op: "Post", URL: "u", Err: http.ErrSchemeMismatch}, false},
		{"an address no connection can have", &url.Error{Op: "Post", URL: "u", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.AddrError{Err: "invalid port", Addr: "65536"}}}, false},
		{"a host the private-network check refused", &url.Error{Op: "Post", URL: "u", Err: fmt.Errorf("pdp resolves to 8.8.8.8: %w", privatenet.ErrNotPrivate)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := transient(tc.err); got != tc.want {
				t.Errorf("transient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// timeoutError is an error that reports a timeout, as net/http's are.
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// malformedCertificateServer serves TLS with a certificate that is not one,
// and returns its address. crypto/tls refuses it with an error of its own
// that is neither an alert nor a verification error.
func malformedCertificateServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("not a certificate")}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	return lis.Addr().String()
}
