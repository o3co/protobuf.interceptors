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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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
				ep, err := NewCedarEndpoint(baseURL)
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
