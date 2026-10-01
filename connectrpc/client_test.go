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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpointtest"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"github.com/o3co/protobuf.interceptors/testproto/testpbconnect"
)

// uploadHandler implements the client-streaming UploadResources RPC. It
// records every message it is handed.
type uploadHandler struct {
	testServiceHandler
	mu       sync.Mutex
	received []string
}

func (h *uploadHandler) UploadResources(_ context.Context, stream *connect.ClientStream[testpb.CreateResourceRequest]) (*connect.Response[testpb.CreateResourceResponse], error) {
	for stream.Receive() {
		h.mu.Lock()
		h.received = append(h.received, stream.Msg().Name)
		h.mu.Unlock()
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&testpb.CreateResourceResponse{Id: "done"}), nil
}

func (h *uploadHandler) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.received...)
}

// upload streams names to UploadResources and returns the RPC's error.
func upload(client testpbconnect.TestServiceClient, names ...string) error {
	stream := client.UploadResources(context.Background())
	stream.RequestHeader().Set("Authorization", "Bearer tok")
	for _, name := range names {
		// A send fails once the server has ended the stream; the error
		// comes from CloseAndReceive.
		if err := stream.Send(&testpb.CreateResourceRequest{Name: name}); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	_, err := stream.CloseAndReceive()
	return err
}

// The interceptors guard handlers. On a client they pass every call through
// untouched, unary and streaming alike.
func TestConnectInterceptors_OnAClient_PassThrough(t *testing.T) {
	impl := &uploadHandler{}
	mux := http.NewServeMux()
	mux.Handle(testpbconnect.NewTestServiceHandler(impl))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var verified bool
	client := testpbconnect.NewTestServiceClient(srv.Client(), srv.URL, connect.WithInterceptors(
		policyconnect.PolicyOptionInterceptor(),
		policyconnect.VerificationInterceptor(endpointtest.Func(func(context.Context, string, string) error {
			verified = true
			return errors.New("a client must not be checked")
		})),
	))

	t.Run("unary", func(t *testing.T) {
		if err := getResource(t, client); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("client stream", func(t *testing.T) {
		if err := upload(client, "a", "b"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if got := impl.all(); len(got) != 2 {
			t.Errorf("handler received %q, want both messages", got)
		}
	})
	if verified {
		t.Error("the verifier was asked on the client side")
	}
}
