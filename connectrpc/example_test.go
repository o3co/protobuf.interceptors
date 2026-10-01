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
	"log"
	"net/http"

	"connectrpc.com/connect"
	policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/o3co/protobuf.interceptors/testproto/testpbconnect"
)

type exampleHandler struct {
	testpbconnect.UnimplementedTestServiceHandler
}

// Pass the interceptors to the service handlers, policy interceptor first.
// Mount handlers built without connect.WithSchema, such as grpchealth and
// grpcreflect, without them: their methods have no descriptor and would be
// refused. testpbconnect stands for your generated package.
func Example() {
	verifier, err := endpoint.NewO3coEndpoint("https://verifier.internal:3000")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle(testpbconnect.NewTestServiceHandler(&exampleHandler{},
		connect.WithInterceptors(
			policyconnect.PolicyOptionInterceptor(),
			policyconnect.VerificationInterceptor(verifier),
		),
	))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
