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

// Package grpc provides grpc-go server interceptors that read a method's
// (o3co.authz.v1.policy) option and have an endpoint.VerifierEndpoint decide
// whether the RPC may run.
//
// PolicyOptionInterceptor and PolicyOptionStreamInterceptor look the method's
// policy up in protoregistry.GlobalFiles and resolve it; VerificationInterceptor
// and VerificationStreamInterceptor read the bearer token and request ID from
// the incoming metadata and ask the endpoint. Chain the policy interceptor
// before the verification interceptor. A method whose descriptor is not
// registered is refused, and a stream is re-checked on every message it
// receives.
//
// The caller is told only a status code and a fixed message; the endpoint's
// error is wrapped by the returned status error and handed to the observer
// set with WithDecisionObserver.
package grpc
