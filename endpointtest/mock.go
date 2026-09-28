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

// Package endpointtest provides test utilities for services using
// protobuf.interceptors. Import this package only from test files.
package endpointtest

import (
	"context"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
)

type mockVerifier struct {
	fn func(ctx context.Context, resource, action string) error
}

func (m *mockVerifier) Verify(ctx context.Context, resource, action string) error {
	return m.fn(ctx, resource, action)
}

// Allow returns a VerifierEndpoint that always grants authorization.
func Allow() endpoint.VerifierEndpoint {
	return &mockVerifier{fn: func(_ context.Context, _, _ string) error { return nil }}
}

// Deny returns a VerifierEndpoint that always denies with a DeniedError.
func Deny() endpoint.VerifierEndpoint {
	return &mockVerifier{fn: func(_ context.Context, _, _ string) error {
		return &interceptors.DeniedError{Reason: "access denied"}
	}}
}

// Func returns a VerifierEndpoint that calls fn on each Verify call.
func Func(fn func(ctx context.Context, resource, action string) error) endpoint.VerifierEndpoint {
	return &mockVerifier{fn: fn}
}

type mockDecisionVerifier struct {
	fn func(ctx context.Context, resource, action string) (*interceptors.Decision, error)
}

func (m *mockDecisionVerifier) Verify(ctx context.Context, resource, action string) error {
	_, err := m.fn(ctx, resource, action)
	return err
}

func (m *mockDecisionVerifier) VerifyDecision(ctx context.Context, resource, action string) (*interceptors.Decision, error) {
	return m.fn(ctx, resource, action)
}

// Decide returns a DecisionVerifier that calls fn on each check, for testing
// what a service does with the decision: the handler reads it with
// interceptors.DecisionFromContext, and a DecisionObserver receives it. A
// denial should be returned as a *interceptors.DeniedError carrying the same
// decision, as the o3co endpoint returns it.
func Decide(fn func(ctx context.Context, resource, action string) (*interceptors.Decision, error)) endpoint.DecisionVerifier {
	return &mockDecisionVerifier{fn: fn}
}
