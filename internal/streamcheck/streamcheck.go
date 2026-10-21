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

// Package streamcheck decides when a stream's authorization is checked
// again. The gRPC and ConnectRPC stream interceptors both use it, so a stream
// is re-checked by the same rule on either framework.
package streamcheck

import (
	"sync"
	"time"
)

// Gate runs a stream's authorization checks.
//
// A check runs unless the last one began less than the interval ago; a zero
// interval runs every check. The first check always runs. The first failure
// is final: every later Check returns it without running anything, and Err
// reports it. Checks never overlap, since a stream may send on one goroutine
// while it receives on another.
type Gate struct {
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	checked bool
	last    time.Time
	err     error
}

// New returns a Gate that runs checks at most once per interval, reading the
// time from now (time.Now when nil). interval must not be negative.
func New(interval time.Duration, now func() time.Time) *Gate {
	if now == nil {
		now = time.Now
	}
	return &Gate{interval: interval, now: now}
}

// Check runs check unless the gate skips it, and returns the gate's failure,
// if any.
func (g *Gate) Check(check func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	start := g.now()
	if g.checked && start.Sub(g.last) < g.interval {
		return nil
	}
	if err := check(); err != nil {
		g.err = err
		return err
	}
	g.checked, g.last = true, start
	return nil
}

// Err returns the failure that ended the stream, or nil.
func (g *Gate) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}
