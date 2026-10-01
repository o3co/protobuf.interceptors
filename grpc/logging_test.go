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
	"io"
	"os"
	"testing"

	"github.com/o3co/protobuf.interceptors/endpointtest"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"google.golang.org/grpc"
)

// A refusal reaches the service through the observer; the stream interceptor
// writes nothing of its own to stderr.
func TestVerificationStreamInterceptor_WritesNothingToStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = stderr }()

	denyOpening := policygrpc.VerificationStreamInterceptor(endpointtest.Deny())
	denyRecheck := policygrpc.VerificationStreamInterceptor(revokedAfter(1))
	_ = denyOpening(nil, &fakeServerStream{ctx: policyStreamCtx()}, streamInfo(), func(any, grpc.ServerStream) error { return nil })
	_ = denyRecheck(nil, &fakeServerStream{ctx: policyStreamCtx()}, streamInfo(), func(_ any, ss grpc.ServerStream) error {
		return ss.RecvMsg(&testpb.CreateResourceRequest{})
	})

	os.Stderr = stderr
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if len(out) != 0 {
		t.Errorf("the stream interceptor wrote to stderr:\n%s", out)
	}
}
