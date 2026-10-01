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

package endpoint_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
)

// The o3co endpoint asks auth.policy-verifier, POST {baseURL}/verify.
func ExampleNewO3coEndpoint() {
	verifier, err := endpoint.NewO3coEndpoint(
		"https://verifier.internal:3000",
		// The shared credential of the verifier's optional http.callerAuth gate.
		endpoint.WithO3coHeaders(map[string]string{
			"x-caller-token": os.Getenv("VERIFIER_CALLER_TOKEN"),
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = verifier // pass it to the verification interceptors
}

// For mutual TLS or a private CA, give the endpoint the transport to send
// over. The OPA and Cedar endpoints take the same with WithOPATransport and
// WithCedarTransport.
func ExampleWithO3coTransport() {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// transport.TLSClientConfig = &tls.Config{RootCAs: ..., Certificates: ...}
	verifier, err := endpoint.NewO3coEndpoint(
		"https://verifier.internal:3000",
		endpoint.WithO3coTransport(transport),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = verifier
}

// The OPA endpoint asks POST {baseURL}/v1/data/{policyPath} and allows when the
// result is true.
func ExampleNewOPAEndpoint() {
	verifier, err := endpoint.NewOPAEndpoint("http://localhost:8181", "authz/allow")
	if err != nil {
		log.Fatal(err)
	}
	_ = verifier
}

// The Cedar agent authenticates nothing, so the endpoint requires a resolver
// that verifies the bearer token and names the principal it stands for.
func ExampleNewCedarEndpoint() {
	verifyJWT := func(ctx context.Context, token string) (subject string, err error) {
		// Verify the signature, expiry, issuer and audience here.
		return "", errors.New("not implemented")
	}
	verifier, err := endpoint.NewCedarEndpoint("http://localhost:8180",
		endpoint.WithCedarPrincipalResolver(verifyJWT),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = verifier
}

// The static endpoint decides locally, on resource and action alone. It still
// requires a bearer token on the context, which the verification interceptors
// put there.
func ExampleNewStaticEndpoint() {
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{
		{Resource: "posts/*", Action: "read"},
	})

	ctx := interceptors.WithBearerToken(context.Background(), "token")
	fmt.Println(verifier.Verify(ctx, "posts/1", "read"))

	var denied *interceptors.DeniedError
	fmt.Println(errors.As(verifier.Verify(ctx, "posts/1", "write"), &denied))
	// Output:
	// <nil>
	// true
}
