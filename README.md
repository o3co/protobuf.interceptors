# protobuf.interceptors

[![CI](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/o3co/protobuf.interceptors.svg)](https://pkg.go.dev/github.com/o3co/protobuf.interceptors)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Framework-agnostic protobuf method option authorization interceptors for Go. Declares access policy (resource + action) in `.proto` method options and enforces it at runtime via pluggable verification backends. Supports both gRPC and ConnectRPC.

## How it works

Define authorization policy directly in your `.proto` files:

```proto
import "policy.proto";

service PostService {
  rpc GetPost(GetPostRequest) returns (Post) {
    option (o3co.authz.v1.policy) = {
      resource: "posts/<id>"
      action: "read"
      field_mappings: [{ placeholder: "id", request_field: "id" }]
    };
  }

  rpc CreatePost(CreatePostRequest) returns (Post) {
    option (o3co.authz.v1.policy) = {
      resource: "posts"
      action: "write"
    };
  }

  // No policy option = no authorization check
  rpc HealthCheck(Empty) returns (Status);
}
```

At runtime, interceptors read the option, resolve field mappings from the request, and call a verification backend:

```text
RPC request
     │
     ▼
┌──────────────────────────────────┐
│  PolicyOptionInterceptor         │  reads (o3co.authz.v1.policy) from proto,
│                                  │  resolves <placeholder> from request fields,
│                                  │  stores Policy{Resource, Action} in ctx
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  VerificationInterceptor         │  reads policy from ctx,
│                                  │  calls VerifierEndpoint.Verify(),
│                                  │  returns PermissionDenied on failure
└───────────────┬──────────────────┘
                │
                ▼
          handler (your code)
```

## Modules

Three independent Go modules with a deliberate separation of concerns:

| Module | Import Path | Dependencies |
|---|---|---|
| Core | `github.com/o3co/protobuf.interceptors` | `google.golang.org/protobuf` + stdlib |
| gRPC | `github.com/o3co/protobuf.interceptors/grpc` | core + `google.golang.org/grpc` |
| ConnectRPC | `github.com/o3co/protobuf.interceptors/connectrpc` | core + `connectrpc.com/connect` |

The core module contains the proto schema, context helpers, error types, resource resolution, and all verification backends. The framework-specific modules provide only the interceptor implementations.

## Installation

```bash
# gRPC users
go get github.com/o3co/protobuf.interceptors/grpc

# ConnectRPC users
go get github.com/o3co/protobuf.interceptors/connectrpc
```

## Usage

### gRPC

```go
import (
    policygrpc "github.com/o3co/protobuf.interceptors/grpc"
    "github.com/o3co/protobuf.interceptors/endpoint"
)

// Create a verification backend
verifier, _ := endpoint.NewOPAEndpoint("http://localhost:8181", "authz/allow")

// Chain interceptors
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
```

### ConnectRPC

```go
import (
    policyconnect "github.com/o3co/protobuf.interceptors/connectrpc"
    "github.com/o3co/protobuf.interceptors/endpoint"
)

verifier, _ := endpoint.NewCedarEndpoint("http://localhost:8180")

mux := http.NewServeMux()
path, handler := foopbconnect.NewFooServiceHandler(
    &fooServer{},
    connect.WithInterceptors(
        policyconnect.PolicyOptionInterceptor(),
        policyconnect.VerificationInterceptor(verifier),
    ),
)
mux.Handle(path, handler)
```

## Verification Backends

The `endpoint` package provides four backends:

| Backend | Constructor | Protocol |
|---|---|---|
| OPA | `endpoint.NewOPAEndpoint(baseURL, policyPath)` | `POST /v1/data/{path}` |
| Cedar Agent | `endpoint.NewCedarEndpoint(baseURL)` | `POST /v1/is_authorized` |
| o3co policy-verifier | `endpoint.NewO3coEndpoint(baseURL)` | `POST /verify` |
| Static rules | `endpoint.NewStaticEndpoint(rules)` | Local evaluation |

All backends implement the `endpoint.VerifierEndpoint` interface:

```go
type VerifierEndpoint interface {
    Verify(ctx context.Context, resource, action string) error
}
```

Bearer token and request ID are passed via `context.Context`, set by the framework-specific `VerificationInterceptor`.

## Proto Schema

The policy extension uses field tag 50000 in the `google.protobuf.MethodOptions` extension range:

```proto
// schema/policy.proto
package o3co.authz.v1;

message FieldMapping {
  string placeholder = 1;
  string request_field = 2;
}

message Policy {
  string resource = 1;
  string action = 2;
  repeated FieldMapping field_mappings = 3;
}

extend google.protobuf.MethodOptions {
  Policy policy = 50000;
}
```

To use in your service protos, import `policy.proto` and add the `schema/` directory to your `protoc` include path.

## Test Helpers

The `endpointtest` package provides mock endpoints for testing:

```go
import "github.com/o3co/protobuf.interceptors/endpointtest"

allow := endpointtest.Allow()   // always allows
deny  := endpointtest.Deny()    // always denies
custom := endpointtest.Func(func(ctx context.Context, resource, action string) error {
    // custom logic
    return nil
})
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
