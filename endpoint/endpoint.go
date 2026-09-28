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

	interceptors "github.com/o3co/protobuf.interceptors"
)

// VerifierEndpoint is the interface for policy verification endpoints.
type VerifierEndpoint interface {
	Verify(ctx context.Context, resource, action string) error
}

// DecisionVerifier is a VerifierEndpoint that can also report the decision
// behind its verdict. The verification interceptors use VerifyDecision when an
// endpoint implements it, and hand the decision to the service; an endpoint
// that implements only VerifierEndpoint keeps working and reports nothing.
type DecisionVerifier interface {
	VerifierEndpoint
	// VerifyDecision is Verify, and also returns what the backend reported
	// behind the verdict. The error is exactly what Verify returns. The
	// decision may be nil with either outcome: nil means the backend reported
	// nothing, which is unknown.
	VerifyDecision(ctx context.Context, resource, action string) (*interceptors.Decision, error)
}

// VerifyWithDecision calls v.VerifyDecision when v is a DecisionVerifier, and
// v.Verify with a nil decision otherwise.
func VerifyWithDecision(ctx context.Context, v VerifierEndpoint, resource, action string) (*interceptors.Decision, error) {
	if dv, ok := v.(DecisionVerifier); ok {
		return dv.VerifyDecision(ctx, resource, action)
	}
	return nil, v.Verify(ctx, resource, action)
}
