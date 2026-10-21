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
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/internal/privatenet"
)

// plainInternalSetup is what a test gives an endpoint besides its base URL.
type plainInternalSetup struct {
	pairs         []string
	allowInsecure bool
	transport     http.RoundTripper
	timeout       time.Duration
	// dialer replaces the private-network dialer's lookup and connect; its
	// zero value leaves both as they are.
	dialer privatenet.Dialer
}

// plainInternalKinds builds each HTTP endpoint with its plain-internal option.
var plainInternalKinds = []struct {
	name   string
	option func(pairs ...string)
	build  func(baseURL string, s plainInternalSetup) (VerifierEndpoint, error)
	client func(VerifierEndpoint) *http.Client
	allow  string
}{
	{
		name:   "o3co",
		option: func(pairs ...string) { WithO3coAllowPlainInternal(pairs...) },
		build: func(baseURL string, s plainInternalSetup) (VerifierEndpoint, error) {
			opts := []O3coOption{
				WithO3coAllowPlainInternal(s.pairs...),
				func(c *o3coBuildConfig) { c.reach.privateDialer = s.dialer },
			}
			if s.allowInsecure {
				opts = append(opts, WithO3coAllowInsecure())
			}
			if s.transport != nil {
				opts = append(opts, WithO3coTransport(s.transport))
			}
			if s.timeout != 0 {
				opts = append(opts, WithO3coTimeout(s.timeout))
			}
			return NewO3coEndpoint(baseURL, opts...)
		},
		client: func(ep VerifierEndpoint) *http.Client { return ep.(*o3coEndpoint).httpClient },
		allow:  allowWithoutEvaluation,
	},
	{
		name:   "opa",
		option: func(pairs ...string) { WithOPAAllowPlainInternal(pairs...) },
		build: func(baseURL string, s plainInternalSetup) (VerifierEndpoint, error) {
			opts := []OPAOption{
				WithOPAAllowPlainInternal(s.pairs...),
				func(c *opaBuildConfig) { c.reach.privateDialer = s.dialer },
			}
			if s.allowInsecure {
				opts = append(opts, WithOPAAllowInsecure())
			}
			if s.transport != nil {
				opts = append(opts, WithOPATransport(s.transport))
			}
			if s.timeout != 0 {
				opts = append(opts, WithOPATimeout(s.timeout))
			}
			return NewOPAEndpoint(baseURL, "authz/allow", opts...)
		},
		client: func(ep VerifierEndpoint) *http.Client { return ep.(*opaEndpoint).httpClient },
		allow:  `{"result": true}`,
	},
	{
		name:   "cedar",
		option: func(pairs ...string) { WithCedarAllowPlainInternal(pairs...) },
		build: func(baseURL string, s plainInternalSetup) (VerifierEndpoint, error) {
			opts := []CedarOption{
				WithCedarPrincipalResolver(tokenAsPrincipal),
				WithCedarAllowPlainInternal(s.pairs...),
				func(c *cedarBuildConfig) { c.reach.privateDialer = s.dialer },
			}
			if s.allowInsecure {
				opts = append(opts, WithCedarAllowInsecure())
			}
			if s.transport != nil {
				opts = append(opts, WithCedarTransport(s.transport))
			}
			if s.timeout != 0 {
				opts = append(opts, WithCedarTimeout(s.timeout))
			}
			return NewCedarEndpoint(baseURL, opts...)
		},
		client: func(ep VerifierEndpoint) *http.Client { return ep.(*cedarEndpoint).httpClient },
		allow:  `{"decision": "Allow"}`,
	},
}

// A listed entry is a host and a port written one way. One that could never
// be reached under the option makes the constructor return an error naming
// it; the option itself does not panic, since entries come from deployment
// configuration.
func TestPlainInternal_InvalidEntry_IsAnError(t *testing.T) {
	invalid := []string{
		"", "pdp", "pdp:", ":8181", "[]:8181",
		"pdp:0", "pdp:65536", "pdp:08181", "pdp:+80", "pdp:http", "pdp:80:80",
		"pdp..:80", ".pdp:80", "a..b:80", "-pdp:80", "pdp-:80", "pdp.-x:80",
		"bücher.example:80", "İdp:80", "\u212Adp:80", "pdp internal:80", "*.internal:80",
		strings.Repeat("a", 64) + ":80",
		strings.Repeat(strings.Repeat("a", 63)+".", 4) + "a:80",
		// A numeric spelling some resolvers read as an address.
		"10.1:80", "2130706433:80", "010.0.0.1:80",
		// An address that is not on a private network.
		"8.8.8.8:80", "127.0.0.1:80", "[::1]:80", "169.254.169.254:80",
		"[::10.0.0.1]:80", "[fd00::1%eth0]:80", "[::ffff:10.0.0.5%eth0]:80",
		"100.100.100.200:80", "[fd00:ec2::254]:80", "[fd00:ec2::23]:80",
		"[fd20:ce::254]:80", "[fd00:a9fe:a9fe::1]:80",
	}
	for _, k := range plainInternalKinds {
		for _, entry := range invalid {
			t.Run(k.name+"/"+entry, func(t *testing.T) {
				// Whatever the base URL: the entry is wrong on its own.
				for _, baseURL := range []string{"https://verifier.internal:3000", "http://policy-verifier:3000"} {
					_, err := k.build(baseURL, plainInternalSetup{pairs: []string{"policy-verifier:3000", entry}})
					if err == nil {
						t.Fatalf("%s: %q was accepted", baseURL, entry)
					}
					if !strings.Contains(err.Error(), strconv.Quote(entry)) || !strings.Contains(err.Error(), "AllowPlainInternal") {
						t.Errorf("%s: error %q names neither the entry %q nor the option", baseURL, err, entry)
					}
				}
			})
		}
	}
}

// The option records a refused entry rather than panicking at the call, and
// the constructor names every refused entry, not only the first.
func TestPlainInternal_InvalidEntries_AreAllNamed(t *testing.T) {
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("the option panicked: %v", r)
					}
				}()
				k.option("", "pdp:0")
			}()
			_, err := k.build("https://verifier.internal:3000", plainInternalSetup{pairs: []string{"", "pdp:80", "pdp:0"}})
			if err == nil {
				t.Fatal("bad entries were accepted")
			}
			for _, entry := range []string{`""`, `"pdp:0"`} {
				if !strings.Contains(err.Error(), entry) {
					t.Errorf("error %q does not name %s", err, entry)
				}
			}
			if strings.Contains(err.Error(), `"pdp:80"`) {
				t.Errorf("error %q names the valid entry", err)
			}
		})
	}
}

// Entries refused across several calls are all named.
func TestPlainInternal_InvalidEntriesAcrossCalls_AreAllNamed(t *testing.T) {
	_, err := NewO3coEndpoint("https://verifier.internal:3000",
		WithO3coAllowPlainInternal(""),
		WithO3coAllowPlainInternal("pdp:80"),
		WithO3coAllowPlainInternal("pdp:0"),
	)
	if err == nil {
		t.Fatal("bad entries were accepted")
	}
	for _, entry := range []string{`""`, `"pdp:0"`} {
		if !strings.Contains(err.Error(), entry) {
			t.Errorf("error %q does not name %s", err, entry)
		}
	}
}

// An entry that carries a user or a URL's scheme or path is refused without
// repeating what precedes the host: a URL from the environment, given in
// place of a host and port, can carry a password, and the error is logged.
func TestPlainInternal_EntryWithCredentials_IsNotEchoed(t *testing.T) {
	for _, k := range plainInternalKinds {
		for _, entry := range []string{
			"http://user:s3cret@pdp:8181", "user:s3cret@pdp:8181", "s3cret@pdp:8181",
			"http://user:s3cret@pdp:8181/path", "http://pdp:8181/s3cret",
			"pdp:8181?token=s3cret", "pdp:8181#s3cret", "user:pa/s3cret@pdp:8181",
		} {
			t.Run(k.name+"/"+entry, func(t *testing.T) {
				_, err := k.build("https://verifier.internal:3000", plainInternalSetup{pairs: []string{entry}})
				if err == nil {
					t.Fatalf("%q was accepted", entry)
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Errorf("error %q repeats the entry's credentials", err)
				}
				if !strings.Contains(err.Error(), "AllowPlainInternal") {
					t.Errorf("error %q does not name the option", err)
				}
			})
		}
	}
}

func TestPlainInternal_ValidEntry_IsAccepted(t *testing.T) {
	valid := []string{
		"policy-verifier:3000", "PDP.Internal:8181", "pdp:1", "pdp:65535",
		"10.0.0.5:8181", "[fd00::5]:8181", "[::ffff:10.0.0.5]:80",
		strings.Repeat("a", 63) + ":80", "1password:80", "a1.b2:80",
		// A Compose service name, and a name written absolute.
		"policy_verifier:3000", "_pdp:80", "pdp.ns.svc.cluster.local.:80",
	}
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			if _, err := k.build("https://verifier.internal:3000", plainInternalSetup{pairs: valid}); err != nil {
				t.Errorf("valid entries: %v", err)
			}
			// A call with no entry lists nothing and is no error.
			if _, err := k.build("https://verifier.internal:3000", plainInternalSetup{}); err != nil {
				t.Errorf("no entries: %v", err)
			}
		})
	}
}

// A listed pair is reached over the endpoint's own transport, which talks to
// that one host:port: its idle pool for the host is the whole pool, not
// net/http's default of two, so concurrent checks — every stream message is
// one — reuse connections.
func TestPlainInternal_TransportKeepsAPoolForTheHost(t *testing.T) {
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			ep, err := k.build("http://pdp:8181", plainInternalSetup{pairs: []string{"pdp:8181"}})
			if err != nil {
				t.Fatal(err)
			}
			tr, ok := k.client(ep).Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport is %T, want *http.Transport", k.client(ep).Transport)
			}
			if tr.MaxIdleConnsPerHost != tr.MaxIdleConns || tr.MaxIdleConnsPerHost <= http.DefaultMaxIdleConnsPerHost {
				t.Errorf("MaxIdleConnsPerHost = %d, MaxIdleConns = %d; want them equal and above %d",
					tr.MaxIdleConnsPerHost, tr.MaxIdleConns, http.DefaultMaxIdleConnsPerHost)
			}
		})
	}
}

// Only the listed host and port take plaintext; the scheme's default port
// counts as written. Loopback and https are as they are without the option.
func TestPlainInternal_AcceptsAListedPairAndNoOther(t *testing.T) {
	pairs := []string{"policy-verifier:3001", "10.0.0.5:8181", "[fd00::5]:8181", "pdp:80", "PDP.Internal:8181", "idp:80", "policy_verifier:3001", "abs.internal.:80"}
	accepted := []string{
		"http://policy-verifier:3001",
		"http://POLICY-VERIFIER:3001/base/",
		"http://10.0.0.5:8181",
		"http://[::ffff:10.0.0.5]:8181",
		"http://[fd00::5]:8181",
		"http://[FD00:0::5]:8181",
		"http://pdp",
		"http://pdp:80",
		"http://pdp.internal:8181",
		// One trailing dot is the same name, on either side.
		"http://policy-verifier.:3001",
		"http://abs.internal",
		"http://abs.internal.",
		"http://policy_verifier:3001",
		"http://localhost:3000",
		"https://policy-verifier.example",
	}
	refused := []string{
		"http://policy-verifier:3002",
		"http://policy-verifier",
		"http://policy-verifier..:3001",
		// An address with a trailing dot is a name, and not the listed address.
		"http://10.0.0.5.:8181",
		"http://other:3001",
		// A name that only folds to a listed one: net/http asks for its
		// IDNA form, another host.
		"http://İdp",
		"http://\u212Adp:80",
		"http://10.0.0.6:8181",
		"http://pdp:080",
		"http://[fd00::5%25eth0]:8181",
		"http://[::ffff:10.0.0.5%25eth0]:8181",
		"http://policy-verifier.example:3001",
	}
	for _, k := range plainInternalKinds {
		for _, baseURL := range accepted {
			t.Run(k.name+"/accepted/"+baseURL, func(t *testing.T) {
				if _, err := k.build(baseURL, plainInternalSetup{pairs: pairs}); err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
		for _, baseURL := range refused {
			t.Run(k.name+"/refused/"+baseURL, func(t *testing.T) {
				_, err := k.build(baseURL, plainInternalSetup{pairs: pairs})
				if err == nil {
					t.Fatal("was accepted")
				}
			})
		}
	}
}

// The refusal names both ways to permit plaintext.
func TestPlainInternal_RefusalNamesTheOptions(t *testing.T) {
	names := map[string][]string{
		"o3co":  {"WithO3coAllowPlainInternal", "WithO3coAllowInsecure"},
		"opa":   {"WithOPAAllowPlainInternal", "WithOPAAllowInsecure"},
		"cedar": {"WithCedarAllowPlainInternal", "WithCedarAllowInsecure"},
	}
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			_, err := k.build("http://policy-verifier:3001", plainInternalSetup{})
			if err == nil {
				t.Fatal("was accepted")
			}
			for _, name := range names[k.name] {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("the error %q does not name %s", err, name)
				}
			}
		})
	}
}

// The address check runs in the endpoint's own transport, so a transport of
// the caller's cannot be used for a listed pair; it can for anything else.
func TestPlainInternal_ListedPairWithATransport_IsRefused(t *testing.T) {
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			rt := http.DefaultTransport
			if _, err := k.build("http://policy-verifier:3001", plainInternalSetup{pairs: []string{"policy-verifier:3001"}, transport: rt}); err == nil {
				t.Error("a listed pair over a caller's transport was accepted")
			}
			if _, err := k.build("http://policy-verifier:3001", plainInternalSetup{pairs: []string{"policy-verifier:3001"}, transport: rt, allowInsecure: true}); err == nil {
				t.Error("a listed pair over a caller's transport was accepted with AllowInsecure")
			}
			if _, err := k.build("https://policy-verifier:3001", plainInternalSetup{pairs: []string{"policy-verifier:3001"}, transport: rt}); err != nil {
				t.Errorf("https with a transport: unexpected error: %v", err)
			}
			if _, err := k.build("http://other:3001", plainInternalSetup{pairs: []string{"policy-verifier:3001"}, transport: rt, allowInsecure: true}); err != nil {
				t.Errorf("an unlisted pair with AllowInsecure and a transport: unexpected error: %v", err)
			}
		})
	}
}

// resolverFunc answers a lookup with the addresses it returns.
type resolverFunc func(host string) []netip.Addr

func (f resolverFunc) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f(host), nil
}

// redirectingDial connects every address it is asked for to target, and
// records the addresses.
type redirectingDial struct {
	target string
	mu     sync.Mutex
	dialed []string
}

func (d *redirectingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.target)
}

func resolvingTo(ss ...string) resolverFunc {
	return func(string) []netip.Addr {
		out := make([]netip.Addr, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParseAddr(s)
		}
		return out
	}
}

// A listed pair is reached only when every address its host resolves to is
// private, checked as the connection is made. That holds with AllowInsecure
// too: a listed pair is always checked.
func TestPlainInternal_ChecksEveryAddressAsItDials(t *testing.T) {
	for _, k := range plainInternalKinds {
		for _, allowInsecure := range []bool{false, true} {
			t.Run(k.name+"/allowInsecure="+strconv.FormatBool(allowInsecure), func(t *testing.T) {
				var reached atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(k.allow))
				}))
				t.Cleanup(srv.Close)
				port := srv.Listener.Addr().(*net.TCPAddr).Port
				pair := net.JoinHostPort("pdp.test", strconv.Itoa(port))
				baseURL := "http://" + pair

				// Private addresses: asked at the first, which reaches the server.
				d := &redirectingDial{target: srv.Listener.Addr().String()}
				ep, err := k.build(baseURL, plainInternalSetup{
					pairs:         []string{pair},
					allowInsecure: allowInsecure,
					dialer:        privatenet.Dialer{Resolver: resolvingTo("10.0.0.7", "fd00::7"), Dial: d.dial},
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if err := ep.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(d.dialed) != 1 || d.dialed[0] != net.JoinHostPort("10.0.0.7", strconv.Itoa(port)) {
					t.Errorf("dialed %v, want only the first private address", d.dialed)
				}

				// One public or loopback address among them: refused before
				// any connection, and the request never reaches the server.
				for _, resolved := range [][]string{{"10.0.0.7", "8.8.8.8"}, {"127.0.0.1"}, {"100.100.100.200"}} {
					d := &redirectingDial{target: srv.Listener.Addr().String()}
					ep, err := k.build(baseURL, plainInternalSetup{
						pairs:         []string{pair},
						allowInsecure: allowInsecure,
						dialer:        privatenet.Dialer{Resolver: resolvingTo(resolved...), Dial: d.dial},
					})
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					err = ep.Verify(ctxWithToken("tok"), "r", "a")
					var denied *interceptors.DeniedError
					if err == nil || errors.As(err, &denied) {
						t.Errorf("%v: got %v, want an error that is not a denial", resolved, err)
					}
					if len(d.dialed) != 0 {
						t.Errorf("%v: dialed %v, want nothing", resolved, d.dialed)
					}
				}
				if n := reached.Load(); n != 1 {
					t.Errorf("the server was asked %d times, want once", n)
				}
			})
		}
	}
}

// A listed pair is reached directly, never through a proxy the environment
// names: the proxy would carry the request in plaintext and resolve the name
// itself.
func TestPlainInternal_UsesNoProxy(t *testing.T) {
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			ep, err := k.build("http://policy-verifier:3001", plainInternalSetup{pairs: []string{"policy-verifier:3001"}})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tr, ok := k.client(ep).Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport is %T, want the endpoint's own *http.Transport", k.client(ep).Transport)
			}
			// Not even http.ProxyFromEnvironment, which reads the environment
			// once per process.
			if tr.Proxy != nil {
				t.Error("the transport has a proxy function")
			}
		})
	}
}

// An address that takes no connection leaves time for the next within the
// endpoint's timeout: net/http dials with a context that carries no deadline,
// so the endpoint bounds the dial itself.
func TestPlainInternal_AnAddressThatDoesNotAnswer_LeavesTimeForTheNext(t *testing.T) {
	for _, k := range plainInternalKinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()
			srv := serve(t, http.StatusOK, k.allow)
			port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
			pair := net.JoinHostPort("pdp.test", port)
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == net.JoinHostPort("10.0.0.7", port) {
					<-ctx.Done() // a dropped SYN
					return nil, ctx.Err()
				}
				var d net.Dialer
				return d.DialContext(ctx, network, srv.Listener.Addr().String())
			}
			ep, err := k.build("http://"+pair, plainInternalSetup{
				pairs:   []string{pair},
				timeout: 6 * time.Second,
				dialer:  privatenet.Dialer{Resolver: resolvingTo("10.0.0.7", "10.0.0.8"), Dial: dial},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err := ep.Verify(ctxWithToken("tok"), "r", "a"); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// A redacted entry keeps the scheme and the host and port, so the operator
// can still find it, and drops what can carry a credential.
func TestRedactedEntry(t *testing.T) {
	for entry, want := range map[string]string{
		"http://user:s3cret@pdp:8181/path": "http://…@pdp:8181…",
		"user:pa/s3cret@pdp:8181":          "…@pdp:8181",
		"http://pdp:8181/s3cret":           "http://pdp:8181…",
		"pdp:8181?token=s3cret":            "pdp:8181…",
		"pdp:8181":                         "pdp:8181",
	} {
		if got := redactedEntry(entry); got != want {
			t.Errorf("redactedEntry(%q) = %q, want %q", entry, got, want)
		}
	}
}
