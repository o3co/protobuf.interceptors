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
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const getResourceProcedure = "/test.v1.TestService/GetResource"

func getResourceDescriptor() protoreflect.MethodDescriptor {
	return testpb.File_test_service_proto.Services().ByName("TestService").Methods().ByName("GetResource")
}

// foreignOptions is a method descriptor whose options are not MethodOptions.
type foreignOptions struct {
	protoreflect.MethodDescriptor
}

func (foreignOptions) Options() proto.Message { return &descriptorpb.ServiceOptions{} }

// serveHandBuilt serves a GetResource handler built by hand with opts, behind
// the interceptors over a verifier that allows everything, and calls it.
func serveHandBuilt(t *testing.T, opts ...connect.HandlerOption) (reached bool, err error) {
	t.Helper()
	var handlerRan atomic.Bool
	opts = append(opts, connect.WithInterceptors(
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Allow()),
	))
	mux := http.NewServeMux()
	mux.Handle(getResourceProcedure, connect.NewUnaryHandler(getResourceProcedure,
		func(context.Context, *connect.Request[testpb.GetResourceRequest]) (*connect.Response[testpb.GetResourceResponse], error) {
			handlerRan.Store(true)
			return connect.NewResponse(&testpb.GetResourceResponse{}), nil
		}, opts...))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := connect.NewClient[testpb.GetResourceRequest, testpb.GetResourceResponse](srv.Client(), srv.URL+getResourceProcedure)
	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")
	_, err = client.CallUnary(context.Background(), req)
	return handlerRan.Load(), err
}

// A handler built without connect.WithSchema has no descriptor to say whether
// it has a policy, so it is refused rather than treated as having none.
func TestConnectChain_HandlerWithoutASchema_IsRefused(t *testing.T) {
	reached, err := serveHandBuilt(t)
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
	if reached {
		t.Error("the handler ran without a schema")
	}
}

func TestConnectChain_SchemaWithForeignOptions_IsRefused(t *testing.T) {
	reached, err := serveHandBuilt(t, connect.WithSchema(foreignOptions{getResourceDescriptor()}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
	if reached {
		t.Error("the handler ran with options the interceptor could not read")
	}
}

// The counterpart: the same hand-built handler with its schema is checked
// and runs.
func TestConnectChain_HandBuiltHandlerWithASchema_Runs(t *testing.T) {
	reached, err := serveHandBuilt(t, connect.WithSchema(getResourceDescriptor()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reached {
		t.Error("the handler did not run")
	}
}

func TestConnectPolicyOption_Streaming_HandlerWithoutASchema_IsRefused(t *testing.T) {
	wrapped := policyconnect.PolicyOptionInterceptor().WrapStreamingHandler(
		func(context.Context, connect.StreamingHandlerConn) error {
			t.Error("the handler ran without a schema")
			return nil
		})
	err := wrapped(context.Background(), &specConn{spec: connect.Spec{Procedure: "/test.v1.TestService/UploadResources"}})
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
}

// specConn is the handler side of a stream with a given spec.
type specConn struct {
	connect.StreamingHandlerConn
	spec connect.Spec
}

func (c *specConn) Spec() connect.Spec { return c.spec }
