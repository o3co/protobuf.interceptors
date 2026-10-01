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
		var opts []CedarOption
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
