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
	interceptors "github.com/o3co/protobuf.interceptors"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"github.com/o3co/protobuf.interceptors/testproto/testpbconnect"
)

// testServiceHandler implements the ConnectRPC TestService.
type testServiceHandler struct {
	// getResourceByIDCalled records whether the handler was reached. Read from
	// the test goroutine while the server writes it, so it is atomic.
	getResourceByIDCalled atomic.Bool
}

func (h *testServiceHandler) GetResource(ctx context.Context, req *connect.Request[testpb.GetResourceRequest]) (*connect.Response[testpb.GetResourceResponse], error) {
	return connect.NewResponse(&testpb.GetResourceResponse{Id: req.Msg.Id, Name: "test"}), nil
}

func (h *testServiceHandler) CreateResource(ctx context.Context, req *connect.Request[testpb.CreateResourceRequest]) (*connect.Response[testpb.CreateResourceResponse], error) {
	return connect.NewResponse(&testpb.CreateResourceResponse{Id: "new-id"}), nil
}

func (h *testServiceHandler) GetResourceById(ctx context.Context, req *connect.Request[testpb.GetResourceByIdRequest]) (*connect.Response[testpb.GetResourceResponse], error) {
	h.getResourceByIDCalled.Store(true)
	return connect.NewResponse(&testpb.GetResourceResponse{Id: req.Msg.Id, Name: "found"}), nil
}

func (h *testServiceHandler) HealthCheck(ctx context.Context, req *connect.Request[testpb.HealthCheckRequest]) (*connect.Response[testpb.HealthCheckResponse], error) {
	return connect.NewResponse(&testpb.HealthCheckResponse{Status: "ok"}), nil
}

func startConnectServer(t *testing.T, interceptorList ...connect.Interceptor) (testpbconnect.TestServiceClient, func()) {
	t.Helper()
	return startConnectServerWithImpl(t, &testServiceHandler{}, interceptorList...)
}

func startConnectServerWithImpl(t *testing.T, impl testpbconnect.TestServiceHandler, interceptorList ...connect.Interceptor) (testpbconnect.TestServiceClient, func()) {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := testpbconnect.NewTestServiceHandler(
		impl,
		connect.WithInterceptors(interceptorList...),
	)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	client := testpbconnect.NewTestServiceClient(srv.Client(), srv.URL)
	return client, srv.Close
}

func TestConnectChain_Allow(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "42"})
	req.Header().Set("Authorization", "Bearer valid-token")

	resp, err := client.GetResource(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Msg.Id != "42" {
		t.Errorf("Id = %q, want %q", resp.Msg.Id, "42")
	}
}

func TestConnectChain_Deny(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResource(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodePermissionDenied)
	}
}

func TestConnectChain_NoPolicyMethod_PassThrough(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Deny()),
	)
	defer cleanup()

	resp, err := client.HealthCheck(context.Background(), connect.NewRequest(&testpb.HealthCheckRequest{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Msg.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Msg.Status, "ok")
	}
}

func TestConnectVerification_MissingPolicyOption_ReturnsInternal(t *testing.T) {
	client, cleanup := startConnectServer(t,
		policyconnect.VerificationInterceptor(endpointtest.Allow()),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResource(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeInternal)
	}
}

func TestConnectVerification_NilVerifier_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	policyconnect.VerificationInterceptor(nil)
}

func TestConnectChain_VerifiesCorrectResourceAction(t *testing.T) {
	var capturedResource, capturedAction string
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, resource, action string) error {
				capturedResource = resource
				capturedAction = action
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResource(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedResource != "resource" {
		t.Errorf("resource = %q, want %q", capturedResource, "resource")
	}
	if capturedAction != "read" {
		t.Errorf("action = %q, want %q", capturedAction, "read")
	}
}

func TestConnectChain_PassesBearerTokenToEndpoint(t *testing.T) {
	var capturedToken string
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, resource, action string) error {
				token, _ := interceptors.BearerTokenFromContext(ctx)
				capturedToken = token
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer my-secret-token")

	_, err := client.GetResource(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedToken != "my-secret-token" {
		t.Errorf("token = %q, want %q", capturedToken, "my-secret-token")
	}
}

func TestConnectChain_FieldMappings_StoresExtractedFieldsInContext(t *testing.T) {
	var capturedFields map[string]string
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, resource, action string) error {
				capturedFields, _ = interceptors.ExtractedFieldsFromContext(ctx)
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceByIdRequest{Id: "abc-123"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResourceById(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedFields == nil {
		t.Fatal("expected extracted fields in context, got nil")
	}
	if capturedFields["id"] != "abc-123" {
		t.Errorf("fields[\"id\"] = %q, want %q", capturedFields["id"], "abc-123")
	}
}

func TestConnectChain_NoFieldMappings_NoExtractedFieldsInContext(t *testing.T) {
	var fieldsPresent bool
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(ctx context.Context, resource, action string) error {
				_, fieldsPresent = interceptors.ExtractedFieldsFromContext(ctx)
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceRequest{Id: "1"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResource(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fieldsPresent {
		t.Error("expected no extracted fields in context for method without field_mappings")
	}
}

// TestConnectChain_PlaceholderValueChangingResourceStructure_IsDenied is the
// ConnectRPC half of the resolution refusal: "resource/<id>" with an id of
// "1.member:2" would name a different resource type to the verifier, so the
// request is denied before any backend is asked and the handler never runs.
func TestConnectChain_PlaceholderValueChangingResourceStructure_IsDenied(t *testing.T) {
	var verified atomic.Bool
	impl := &testServiceHandler{}
	client, cleanup := startConnectServerWithImpl(t, impl,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(context.Context, string, string) error {
				verified.Store(true)
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceByIdRequest{Id: "1.member:2"})
	req.Header().Set("Authorization", "Bearer tok")

	_, err := client.GetResourceById(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Errorf("code = %v, want %v (an unmapped error must not read as a server fault)", got, connect.CodePermissionDenied)
	}
	if impl.getResourceByIDCalled.Load() {
		t.Error("handler was reached for a refused resource value")
	}
	if verified.Load() {
		t.Error("verifier was called with a resource string that should never have been built")
	}
}

func TestConnectChain_PlaceholderValueWithinGrammar_IsResolved(t *testing.T) {
	var capturedResource string
	client, cleanup := startConnectServer(t,
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(
			func(_ context.Context, resource, _ string) error {
				capturedResource = resource
				return nil
			},
		)),
	)
	defer cleanup()

	req := connect.NewRequest(&testpb.GetResourceByIdRequest{Id: "42"})
	req.Header().Set("Authorization", "Bearer tok")

	resp, err := client.GetResourceById(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Msg.Id != "42" {
		t.Errorf("Id = %q, want %q", resp.Msg.Id, "42")
	}
	if capturedResource != "resource/42" {
		t.Errorf("resource = %q, want %q", capturedResource, "resource/42")
	}
}
