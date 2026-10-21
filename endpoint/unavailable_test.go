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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
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
			assertNotUnavailable(t, b.build(t, stall(t, "").URL).Verify(ctx, "r", "a"))
		})
		t.Run(b.name+"/reading the body", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctxWithToken("tok"), 50*time.Millisecond)
			defer cancel()
			assertNotUnavailable(t, b.build(t, stall(t, b.allow[:5]).URL).Verify(ctx, "r", "a"))
		})
	}
}
