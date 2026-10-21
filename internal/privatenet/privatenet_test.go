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

package privatenet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestContains(t *testing.T) {
	inside := []string{
		"10.0.0.0", "10.255.255.255",
		"100.64.0.0", "100.127.255.255",
		"172.16.0.0", "172.31.255.255",
		"192.168.0.0", "192.168.255.255",
		"fc00::", "fd12:3456::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		// An IPv4 address mapped into IPv6 is reached as that IPv4 address.
		"::ffff:10.0.0.1", "::ffff:192.168.1.1",
	}
	outside := []string{
		"9.255.255.255", "11.0.0.0",
		"100.63.255.255", "100.128.0.0",
		"172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0",
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"169.254.169.254", "fe80::1",
		"8.8.8.8", "2001:4860:4860::8888", "2001:db8::1",
		"fe00::1", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		// Only a mapped address is the IPv4 one; the other IPv6 forms that
		// carry one are not reached at it.
		"::10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::",
		// Cloud metadata addresses inside the private ranges.
		"100.100.100.200", "::ffff:100.100.100.200", "fd00:ec2::254", "fd00:ec2::23",
		"fd20:ce::254", "fd00:a9fe:a9fe::1",
		// A zoned address is never private, mapped or not: the zone names a
		// link, and dropping it would reach another address.
		"fd00::1%eth0", "::ffff:10.0.0.5%eth0", "::ffff:192.168.1.1%0",
	}
	for _, s := range inside {
		if !Contains(netip.MustParseAddr(s)) {
			t.Errorf("Contains(%s) = false, want true", s)
		}
	}
	for _, s := range outside {
		if Contains(netip.MustParseAddr(s)) {
			t.Errorf("Contains(%s) = true, want false", s)
		}
	}
	if Contains(netip.Addr{}) {
		t.Error("Contains(zero Addr) = true, want false")
	}
}

// fakeResolver answers every name with addrs, or err.
type fakeResolver struct {
	addrs   []netip.Addr
	err     error
	lookups []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.lookups = append(r.lookups, network+" "+host)
	return r.addrs, r.err
}

// recordingDial records each address it is asked to connect to, and fails
// those in failing; any other it answers with one end of a pipe.
type recordingDial struct {
	dialed  []string
	failing []string
}

func (d *recordingDial) dial(_ context.Context, network, address string) (net.Conn, error) {
	d.dialed = append(d.dialed, network+" "+address)
	if slices.Contains(d.failing, address) {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestDialer_ConnectsOnlyWhenEveryAddressIsPrivate(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		resolved []netip.Addr
		failing  []string
		lookup   bool
		dialed   []string
		refused  bool
		// notPrivate is set when the refusal is for an address that is not
		// private, rather than for want of one.
		notPrivate bool
	}{
		{
			name:     "a name resolving to private addresses",
			address:  "pdp.internal:8181",
			resolved: addrs("10.0.0.7", "fd00::7"),
			lookup:   true,
			dialed:   []string{"tcp 10.0.0.7:8181"},
		},
		{
			name:     "the next address when one cannot be reached",
			address:  "pdp.internal:8181",
			resolved: addrs("10.0.0.7", "fd00::7"),
			failing:  []string{"10.0.0.7:8181"},
			lookup:   true,
			dialed:   []string{"tcp 10.0.0.7:8181", "tcp [fd00::7]:8181"},
		},
		{
			name:     "an IPv4 address mapped into IPv6, at the IPv4 address",
			address:  "pdp.internal:80",
			resolved: addrs("::ffff:192.168.3.4"),
			lookup:   true,
			dialed:   []string{"tcp 192.168.3.4:80"},
		},
		{
			name:       "one public address among private ones",
			address:    "pdp.internal:8181",
			resolved:   addrs("10.0.0.7", "203.0.114.1"),
			lookup:     true,
			refused:    true,
			notPrivate: true,
		},
		{
			name:       "a loopback address",
			address:    "pdp.internal:8181",
			resolved:   addrs("127.0.0.1"),
			lookup:     true,
			refused:    true,
			notPrivate: true,
		},
		{
			name:       "a metadata address",
			address:    "pdp.internal:80",
			resolved:   addrs("100.100.100.200"),
			lookup:     true,
			refused:    true,
			notPrivate: true,
		},
		{
			name:    "no address at all",
			address: "pdp.internal:8181",
			lookup:  true,
			refused: true,
		},
		{
			name:    "a private literal, without a lookup",
			address: "[fd00::9]:8181",
			dialed:  []string{"tcp [fd00::9]:8181"},
		},
		{
			name:       "a zoned address among private ones",
			address:    "pdp.internal:8181",
			resolved:   addrs("10.0.0.7", "::ffff:10.0.0.8%eth0"),
			lookup:     true,
			refused:    true,
			notPrivate: true,
		},
		{
			name:       "a zoned literal mapping a private address",
			address:    "[::ffff:10.0.0.9%eth0]:8181",
			refused:    true,
			notPrivate: true,
		},
		{
			name:       "a public literal",
			address:    "8.8.8.8:80",
			refused:    true,
			notPrivate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeResolver{addrs: tt.resolved}
			d := &recordingDial{failing: tt.failing}
			dialer := &Dialer{Resolver: r, Dial: d.dial}

			conn, err := dialer.DialContext(context.Background(), "tcp", tt.address)
			if conn != nil {
				_ = conn.Close()
			}
			if tt.refused {
				if err == nil {
					t.Fatal("expected the connection to be refused")
				}
				if len(d.dialed) != 0 {
					t.Errorf("dialed %v, want nothing", d.dialed)
				}
				if got := errors.Is(err, ErrNotPrivate); got != tt.notPrivate {
					t.Errorf("errors.Is(%v, ErrNotPrivate) = %v, want %v", err, got, tt.notPrivate)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(d.dialed, tt.dialed) {
				t.Errorf("dialed %v, want %v", d.dialed, tt.dialed)
			}
			if got := len(r.lookups) > 0; got != tt.lookup {
				t.Errorf("looked up %v, want a lookup: %v", r.lookups, tt.lookup)
			}
		})
	}
}

func TestDialer_LooksUpTheFamilyTheNetworkNames(t *testing.T) {
	for network, want := range map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6"} {
		r := &fakeResolver{addrs: addrs("10.0.0.1")}
		d := &recordingDial{}
		conn, err := (&Dialer{Resolver: r, Dial: d.dial}).DialContext(context.Background(), network, "pdp:80")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", network, err)
		}
		_ = conn.Close()
		if !slices.Equal(r.lookups, []string{want + " pdp"}) {
			t.Errorf("%s: looked up %v, want %q", network, r.lookups, want+" pdp")
		}
	}
}

func TestDialer_FailsWhenNothingCanBeReached(t *testing.T) {
	lookupErr := errors.New("no such host")
	r := &fakeResolver{err: lookupErr}
	d := &recordingDial{}
	if _, err := (&Dialer{Resolver: r, Dial: d.dial}).DialContext(context.Background(), "tcp", "pdp:80"); !errors.Is(err, lookupErr) {
		t.Errorf("got %v, want the lookup's error", err)
	}

	r = &fakeResolver{addrs: addrs("10.0.0.1", "10.0.0.2")}
	d = &recordingDial{failing: []string{"10.0.0.1:80", "10.0.0.2:80"}}
	if _, err := (&Dialer{Resolver: r, Dial: d.dial}).DialContext(context.Background(), "tcp", "pdp:80"); err == nil {
		t.Error("expected an error when no address can be reached")
	}
	if len(d.dialed) != 2 {
		t.Errorf("dialed %v, want both addresses", d.dialed)
	}
}

func TestDialer_RefusesAnAddressWithoutAPort(t *testing.T) {
	d := &recordingDial{}
	if _, err := (&Dialer{Resolver: &fakeResolver{}, Dial: d.dial}).DialContext(context.Background(), "tcp", "pdp"); err == nil {
		t.Error("expected an error for an address without a port")
	}
}

// deadlineDial records the deadline each attempt is given, and fails every one.
type deadlineDial struct {
	deadlines []time.Time
}

func (d *deadlineDial) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	deadline, _ := ctx.Deadline()
	d.deadlines = append(d.deadlines, deadline)
	return nil, errors.New("connection timed out")
}

// An address that does not answer leaves time for the next: each attempt has
// a share of what remains of the deadline, as net.Dialer gives one.
func TestDialer_SharesTheDeadlineAmongTheAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	overall, _ := ctx.Deadline()
	r := &fakeResolver{addrs: addrs("fd00::7", "10.0.0.7")}
	d := &deadlineDial{}
	if _, err := (&Dialer{Resolver: r, Dial: d.dial}).DialContext(ctx, "tcp", "pdp:80"); err == nil {
		t.Fatal("expected an error")
	}
	if len(d.deadlines) != 2 {
		t.Fatalf("dialed %d times, want 2", len(d.deadlines))
	}
	if first := d.deadlines[0]; first.IsZero() || !first.Before(overall.Add(-4*time.Second)) {
		t.Errorf("the first attempt's deadline is %v, want about half of the %v left", time.Until(first), time.Until(overall))
	}
	if last := d.deadlines[1]; !last.Equal(overall) {
		t.Errorf("the last attempt's deadline is %v, want the whole of it, %v", last, overall)
	}
}

// With no Resolver or Dial, the system's are used; both honour the context.
func TestDialer_Defaults_HonourTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, address := range []string{"10.0.0.1:80", "pdp.invalid:80"} {
		if _, err := (&Dialer{}).DialContext(ctx, "tcp", address); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: got %v, want context.Canceled", address, err)
		}
	}
}

// Timeout bounds the dial where ctx has no deadline, as net/http's does not,
// and is what the attempts share; zero is the default.
func TestDialer_Timeout_BoundsADialWithoutADeadline(t *testing.T) {
	for _, tt := range []struct {
		timeout time.Duration
		share   time.Duration
	}{
		{4 * time.Second, 2 * time.Second},
		{0, defaultTimeout / 2},
	} {
		r := &fakeResolver{addrs: addrs("10.0.0.7", "10.0.0.8")}
		d := &deadlineDial{}
		start := time.Now()
		if _, err := (&Dialer{Resolver: r, Dial: d.dial, Timeout: tt.timeout}).DialContext(context.Background(), "tcp", "pdp:80"); err == nil {
			t.Fatal("expected an error")
		}
		if len(d.deadlines) != 2 {
			t.Fatalf("dialed %d times, want 2", len(d.deadlines))
		}
		if got := d.deadlines[0].Sub(start); got > tt.share+100*time.Millisecond || got < tt.share-time.Second {
			t.Errorf("Timeout %v: the first attempt had %v, want about %v", tt.timeout, got, tt.share)
		}
	}
}
