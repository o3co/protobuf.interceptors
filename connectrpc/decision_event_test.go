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

package connectrpc_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"github.com/o3co/protobuf.interceptors/testproto/testpbconnect"
)

// fakeClock is a time source the endpoint moves by hand, so the time an
// endpoint call took is exact.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// takes is an endpoint whose n-th call (from 1) takes durations[n-1] by the
// clock, and allows.
func takes(clock *fakeClock, durations ...time.Duration) endpoint.VerifierEndpoint {
	var mu sync.Mutex
	calls := 0
	return endpointtest.Func(func(context.Context, string, string) error {
		mu.Lock()
		d := durations[calls]
		calls++
		mu.Unlock()
		clock.advance(d)
		return nil
	})
}

func TestConnectChain_DecisionEvent_Unary_ProcedureDurationPhase(t *testing.T) {
	clock := newFakeClock()
	rec := &recorder{}
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(takes(clock, 250*time.Millisecond),
			policyconnect.WithDecisionObserver(rec.observe), policyconnect.WithClock(clock.now)),
	)
	defer cleanup()

	if err := getResource(t, client); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	events := rec.all()
	if len(events) != 1 {
		t.Fatalf("observer saw %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Procedure != testpbconnect.TestServiceGetResourceProcedure {
		t.Errorf("Procedure = %q, want %q", ev.Procedure, testpbconnect.TestServiceGetResourceProcedure)
	}
	if ev.Duration != 250*time.Millisecond {
		t.Errorf("Duration = %v, want 250ms", ev.Duration)
	}
	if ev.Phase != interceptors.CheckOpen {
		t.Errorf("Phase = %q, want %q", ev.Phase, interceptors.CheckOpen)
	}
}

// A credential refused before any backend is asked took no endpoint time.
func TestConnectChain_DecisionEvent_Unary_RefusedCredential_ZeroDuration(t *testing.T) {
	clock := newFakeClock()
	rec := &recorder{}
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(takes(clock, time.Second),
			policyconnect.WithDecisionObserver(rec.observe), policyconnect.WithClock(clock.now)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Basic dXNlcjpwYXNz")
	if _, err := client.GetResource(context.Background(), req); err == nil {
		t.Fatal("a refused credential was allowed")
	}
	events := rec.all()
	if len(events) != 1 {
		t.Fatalf("observer saw %d events, want 1", len(events))
	}
	if ev := events[0]; ev.Duration != 0 || ev.Err == nil || ev.Procedure != testpbconnect.TestServiceGetResourceProcedure || ev.Phase != interceptors.CheckOpen {
		t.Errorf("event = %+v, want the refusal with Duration 0, the procedure and CheckOpen", ev)
	}
}

const streamProcedure = "/test.v1.TestService/UploadResources"

func TestConnectVerification_DecisionEvent_Streaming_ProcedureDurationPhase(t *testing.T) {
	clock := newFakeClock()
	rec := &recorder{}
	handler := policyconnect.VerificationInterceptor(
		takes(clock, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond),
		policyconnect.WithDecisionObserver(rec.observe), policyconnect.WithClock(clock.now)).
		WrapStreamingHandler(func(_ context.Context, conn connect.StreamingHandlerConn) error {
			if err := conn.Send("out"); err != nil {
				return err
			}
			return conn.Receive(new(string))
		})
	conn := &sendingConn{fakeStreamingConn: fakeStreamingConn{
		header: http.Header{"Authorization": {"Bearer tok"}},
		spec:   connect.Spec{Procedure: streamProcedure, StreamType: connect.StreamTypeBidi},
	}}

	if err := handler(policyStreamCtx(), conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var phases []interceptors.CheckPhase
	var durations []time.Duration
	for _, ev := range rec.all() {
		if ev.Procedure != streamProcedure {
			t.Errorf("Procedure = %q, want %q", ev.Procedure, streamProcedure)
		}
		phases = append(phases, ev.Phase)
		durations = append(durations, ev.Duration)
	}
	if want := []interceptors.CheckPhase{interceptors.CheckOpen, interceptors.CheckSend, interceptors.CheckReceive}; !slices.Equal(phases, want) {
		t.Errorf("phases = %v, want %v", phases, want)
	}
	if want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}; !slices.Equal(durations, want) {
		t.Errorf("durations = %v, want %v", durations, want)
	}
}

// A stream whose credential is refused at the opening check took no endpoint
// time.
func TestConnectVerification_DecisionEvent_Streaming_RefusedCredential_ZeroDuration(t *testing.T) {
	clock := newFakeClock()
	rec := &recorder{}
	handler := policyconnect.VerificationInterceptor(takes(clock, time.Second),
		policyconnect.WithDecisionObserver(rec.observe), policyconnect.WithClock(clock.now)).
		WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error { return nil })
	conn := &fakeStreamingConn{
		header: http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}},
		spec:   connect.Spec{Procedure: streamProcedure, StreamType: connect.StreamTypeBidi},
	}

	if err := handler(policyStreamCtx(), conn); err == nil {
		t.Fatal("a refused credential opened the stream")
	}
	events := rec.all()
	if len(events) != 1 {
		t.Fatalf("observer saw %d events, want 1", len(events))
	}
	if ev := events[0]; ev.Duration != 0 || ev.Err == nil || ev.Procedure != streamProcedure || ev.Phase != interceptors.CheckOpen {
		t.Errorf("event = %+v, want the refusal with Duration 0, the procedure and CheckOpen", ev)
	}
}

// A request with no token is the endpoint's to refuse, so its call is timed.
func TestConnectChain_DecisionEvent_Unary_NoToken_TheEndpointCallIsTimed(t *testing.T) {
	clock := newFakeClock()
	rec := &recorder{}
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(takes(clock, 5*time.Millisecond),
			policyconnect.WithDecisionObserver(rec.observe), policyconnect.WithClock(clock.now)),
	)
	defer cleanup()

	_, _ = client.GetResource(context.Background(), connect.NewRequest(&testpb.GetResourceRequest{Id: "1"}))
	events := rec.all()
	if len(events) != 1 || events[0].Duration != 5*time.Millisecond {
		t.Errorf("events = %+v, want one with Duration 5ms", events)
	}
}
