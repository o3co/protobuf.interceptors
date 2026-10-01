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

// Package connectrpc provides ConnectRPC interceptors that read a method's
// (o3co.authz.v1.policy) option and have an endpoint.VerifierEndpoint decide
// whether the RPC may run.
//
// PolicyOptionInterceptor reads the policy from the method descriptor the
// handler was built with (connect.WithSchema) and resolves it;
// VerificationInterceptor reads the bearer token and request ID from the
// request headers and asks the endpoint. Pass both to a handler, the policy
// interceptor first. A handler built without a schema is refused, and a
// stream is re-checked on every message it receives. Passed to a client,
// both interceptors let every call through untouched.
//
// The caller is told only a code and a fixed message; the endpoint's error is
// wrapped by the returned error and handed to the observer set with
// WithDecisionObserver.
package connectrpc
