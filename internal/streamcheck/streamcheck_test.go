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

package streamcheck_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/o3co/protobuf.interceptors/internal/streamcheck"
)

// clock is a time source the test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time              { return c.t }
func (c *clock) advance(d time.Duration)     { c.t = c.t.Add(d) }
func newClock() *clock                       { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func counting(n *int) func() error           { return func() error { *n++; return nil } }
func failing(err error, n *int) func() error { return func() error { *n++; return err } }

func TestGate_ZeroInterval_ChecksEveryTime(t *testing.T) {
	g := streamcheck.New(0, newClock().now)
	calls := 0
	for range 3 {
		if err := g.Check(counting(&calls)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if calls != 3 {
		t.Errorf("checks run = %d, want 3", calls)
	}
}

func TestGate_Interval_SkipsUntilItHasPassed(t *testing.T) {
	c := newClock()
	g := streamcheck.New(time.Minute, c.now)
	calls := 0

	_ = g.Check(counting(&calls)) // the first check always runs
	c.advance(59 * time.Second)
	_ = g.Check(counting(&calls))
	if calls != 1 {
		t.Fatalf("checks run = %d, want 1: the last check is younger than the interval", calls)
	}
	c.advance(time.Second)
	_ = g.Check(counting(&calls))
	if calls != 2 {
		t.Fatalf("checks run = %d, want 2: the interval has passed", calls)
	}
	c.advance(30 * time.Second)
	_ = g.Check(counting(&calls))
	if calls != 2 {
		t.Errorf("checks run = %d, want 2: the interval restarts at each check", calls)
	}
}

// The interval runs from when the last check started, so time spent waiting
// for the verifier is not added to it.
func TestGate_Interval_RunsFromTheStartOfTheCheck(t *testing.T) {
	c := newClock()
	g := streamcheck.New(time.Minute, c.now)
	calls := 0

	_ = g.Check(func() error { calls++; c.advance(40 * time.Second); return nil })
	c.advance(20 * time.Second)
	_ = g.Check(counting(&calls))
	if calls != 2 {
		t.Errorf("checks run = %d, want 2", calls)
	}
}

func TestGate_FailureIsFinal(t *testing.T) {
	c := newClock()
	g := streamcheck.New(0, c.now)
	denied := errors.New("denied")
	calls := 0

	if err := g.Err(); err != nil {
		t.Fatalf("Err() = %v before any failure, want nil", err)
	}
	_ = g.Check(counting(&calls))
	if err := g.Check(failing(denied, &calls)); err != denied {
		t.Fatalf("Check() = %v, want the failure", err)
	}
	if err := g.Check(counting(&calls)); err != denied {
		t.Errorf("Check() after a failure = %v, want the same failure", err)
	}
	if calls != 2 {
		t.Errorf("checks run = %d, want 2: nothing is asked after a failure", calls)
	}
	if err := g.Err(); err != denied {
		t.Errorf("Err() = %v, want the failure", err)
	}
}

// A failure within the interval of the last allowed check is still final:
// the interval only skips checks, it never forgets a refusal.
func TestGate_FailureIsFinal_WithInterval(t *testing.T) {
	c := newClock()
	g := streamcheck.New(time.Hour, c.now)
	denied := errors.New("denied")
	calls := 0

	_ = g.Check(failing(denied, &calls))
	if err := g.Check(counting(&calls)); err != denied {
		t.Errorf("Check() = %v, want the failure", err)
	}
	if calls != 1 {
		t.Errorf("checks run = %d, want 1", calls)
	}
}

// A gRPC stream may send on one goroutine while it receives on another, so
// checks are serialized.
func TestGate_ConcurrentChecks_AreSerialized(t *testing.T) {
	g := streamcheck.New(0, time.Now)
	calls := 0 // unsynchronized on purpose: the race detector reports overlap
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.Check(counting(&calls))
		}()
	}
	wg.Wait()
	if calls != 8 {
		t.Errorf("checks run = %d, want 8", calls)
	}
}

func TestGate_NilClock_UsesTheSystemClock(t *testing.T) {
	g := streamcheck.New(time.Hour, nil)
	calls := 0
	_ = g.Check(counting(&calls))
	_ = g.Check(counting(&calls))
	if calls != 1 {
		t.Errorf("checks run = %d, want 1", calls)
	}
}
