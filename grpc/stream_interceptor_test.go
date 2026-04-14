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

package grpc_test

import (
	"testing"

	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
)

func TestPolicyOptionStreamInterceptor_NotNil(t *testing.T) {
	interceptor := policygrpc.PolicyOptionStreamInterceptor()
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}

func TestVerificationStreamInterceptor_NilVerifier_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil verifier")
		}
	}()
	policygrpc.VerificationStreamInterceptor(nil)
}

func TestVerificationStreamInterceptor_NotNil(t *testing.T) {
	interceptor := policygrpc.VerificationStreamInterceptor(endpointtest.Allow())
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}
