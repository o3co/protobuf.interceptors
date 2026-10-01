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

// Package interceptors is the framework-neutral core of protobuf.interceptors:
// authorization enforcement for RPCs whose access policy is declared as a
// protobuf method option, (o3co.authz.v1.policy), defined in package schema.
//
// It holds what the gRPC and ConnectRPC modules share:
//
//   - resolution of a method's policy into the resource and action a backend
//     is asked about (ResolveResource, ResolveResourceWithFields), refusing a
//     request field value that would change which resource the string names;
//   - the bearer token and request ID read from an inbound request
//     (InboundBearerToken, InboundRequestID);
//   - the errors an authorization check ends in (DeniedError, UnauthenticatedError,
//     UnconfirmedRevisionError, ResourceValueError);
//   - the decision a backend reports behind a verdict (Decision,
//     DecisionObserver);
//   - the context plumbing that carries all of it from one interceptor to the
//     next and on to the backend.
//
// The interceptors themselves live in the framework modules,
// github.com/o3co/protobuf.interceptors/grpc and
// github.com/o3co/protobuf.interceptors/connectrpc, and the backends in
// package endpoint. The allow or deny decision is never taken here: it is the
// backend's.
package interceptors
