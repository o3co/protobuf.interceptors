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
	"context"
	"log"
	"net"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	policygrpc "github.com/o3co/protobuf.interceptors/grpc"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
	"google.golang.org/grpc"
)

type exampleServer struct {
	testpb.UnimplementedTestServiceServer
}

// Chain each policy interceptor before its verification interceptor, for unary
// and streaming RPCs alike. testpb stands for your generated package.
func Example() {
	verifier, err := endpoint.NewO3coEndpoint("https://verifier.internal:3000")
	if err != nil {
		log.Fatal(err)
	}

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			policygrpc.PolicyOptionInterceptor(),
			policygrpc.VerificationInterceptor(verifier),
		),
		grpc.ChainStreamInterceptor(
			policygrpc.PolicyOptionStreamInterceptor(),
			policygrpc.VerificationStreamInterceptor(verifier),
		),
	)
	testpb.RegisterTestServiceServer(srv, &exampleServer{})

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(lis))
}

// The observer sees every check, denials included, with the endpoint's error
// before it is mapped for the caller.
func ExampleWithDecisionObserver() {
	verifier, err := endpoint.NewO3coEndpoint("https://verifier.internal:3000")
	if err != nil {
		log.Fatal(err)
	}

	observe := func(ctx context.Context, ev interceptors.DecisionEvent) {
		requestID := interceptors.RequestIDFromContext(ctx)
		log.Printf("authz %s %s request_id=%s err=%v", ev.Action, ev.Resource, requestID, ev.Err)
	}

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			policygrpc.PolicyOptionInterceptor(),
			policygrpc.VerificationInterceptor(verifier, policygrpc.WithDecisionObserver(observe)),
		),
	)
	_ = srv
}
