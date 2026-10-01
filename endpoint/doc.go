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

// Package endpoint holds the authorization backends the verification
// interceptors ask: VerifierEndpoint, and its implementations for
// auth.policy-verifier (NewO3coEndpoint), OPA (NewOPAEndpoint), a Cedar agent
// (NewCedarEndpoint) and a fixed rule list (NewStaticEndpoint).
//
// An endpoint is asked about a resolved resource and action, and reads the
// bearer token and request ID from the context the interceptors put them on.
// Its error tells the interceptors the verdict: nil allows,
// *interceptors.DeniedError denies, *interceptors.UnauthenticatedError refuses
// the credential, and anything else is a failure to decide. The HTTP
// endpoints refuse plaintext to a host other than loopback unless allowed,
// follow no redirects, and bound what they read of a response.
package endpoint
