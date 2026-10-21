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

// Package privatenet decides which addresses are on a private network, and
// connects only to those.
//
// The private networks are 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12,
// 192.168.0.0/16 and fc00::/7. The cloud metadata addresses inside them are
// not private. An IPv4 address mapped into IPv6 is judged as the IPv4 address
// a connection reaches; no other IPv6 form that carries an IPv4 address is.
package privatenet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// metadataAddresses are the cloud metadata services that sit inside
// privateRanges: Alibaba Cloud's, AWS's over IPv6 and Google Cloud's over
// IPv6. The others sit in link-local, which is not private.
var metadataAddresses = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

// Contains reports whether addr is on a private network and is not a cloud
// metadata address. A zoned address is not, an IPv4-mapped one included:
// the zone names a link, and unmapping drops it, which would reach another
// address than the one written.
func Contains(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if slices.Contains(metadataAddresses, addr) {
		return false
	}
	for _, p := range privateRanges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ErrNotPrivate is wrapped by the error DialContext returns when it refuses
// a host because an address it resolves to is not private: a refusal of
// this package's, not a failure of the network.
var ErrNotPrivate = errors.New("not on a private network")

// Resolver looks up the addresses of a host. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer connects to a host only when every address it resolves to is
// private. It resolves the host once and connects to the addresses it
// checked, written as addresses, so no second lookup can answer otherwise.
type Dialer struct {
	// Resolver looks up a host's addresses. Nil is net.DefaultResolver.
	Resolver Resolver
	// Dial connects to one address, written as an IP and port. Nil is a
	// net.Dialer with http.DefaultTransport's keep-alive.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Timeout bounds a whole DialContext, the lookup and every attempt.
	// Zero is defaultTimeout. net/http dials under a context that carries no
	// deadline of the request's, so this is what shares time among the
	// addresses.
	Timeout time.Duration
}

// defaultTimeout is http.DefaultTransport's dial timeout.
const defaultTimeout = 30 * time.Second

var defaultDialer = &net.Dialer{KeepAlive: 30 * time.Second}

// DialContext connects to address, a host and port, at the first of the
// host's addresses that answers, trying them in turn within Timeout; while
// more than one is left to try, an attempt has its share of the time left,
// as with a net.Dialer. It refuses before connecting at all when the host
// resolves to no address or to any address that is not private.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else {
		resolver := d.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addrs, err = resolver.LookupNetIP(ctx, lookupNetwork(network), host)
		if err != nil {
			return nil, err
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s resolves to no address", host)
	}
	for _, addr := range addrs {
		if !Contains(addr) {
			return nil, fmt.Errorf("%s resolves to %s: %w", host, addr, ErrNotPrivate)
		}
	}

	dial := d.Dial
	if dial == nil {
		dial = defaultDialer.DialContext
	}
	var errs []error
	for i, addr := range addrs {
		attemptCtx, cancel := attemptContext(ctx, len(addrs)-i)
		conn, err := dial(attemptCtx, network, net.JoinHostPort(addr.Unmap().String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// minAttempt is the least time an attempt is given while others are left,
// net.Dialer's own floor.
const minAttempt = 2 * time.Second

// attemptContext returns ctx bounded to the share of its deadline one of
// remaining addresses has: what is left divided among them, at least
// minAttempt, never past ctx's own. Without a deadline, or for the last
// address, it is ctx.
func attemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || remaining <= 1 {
		return ctx, func() {}
	}
	left := time.Until(deadline)
	share := max(left/time.Duration(remaining), minAttempt)
	if share >= left {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, share)
}

// lookupNetwork is the address family a lookup for network asks for.
func lookupNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}
