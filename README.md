# protobuf.interceptors

[![CI](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/o3co/protobuf.interceptors.svg)](https://pkg.go.dev/github.com/o3co/protobuf.interceptors)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> This repository handles **authorization enforcement** (gRPC / ConnectRPC) in the three-layer separation of concerns ([authentication & token issuance](https://github.com/o3co/auth.provider) / [authorization decision](https://github.com/o3co/auth.policy-verifier) / authorization enforcement) of the [auth](https://github.com/o3co/auth) stack — delegating the allow/deny decision to auth.policy-verifier, OPA, Cedar, or any other `VerifierEndpoint`.

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

### Placeholder values

A `<placeholder>` is filled from a request field, which the caller controls, and
the result is parsed by the authorization backend. So a value is only allowed to
fill one part of the resource string — never to change its structure.

Resolution refuses a value unless every character of it is in the segment token
of [auth.policy-verifier]'s dot-notation grammar: **printable ASCII except space,
`"`, `\`, `.` and `:`**. An empty value is refused too, since it deletes a
component of the template instead of filling it. `/`, `-`, `_`, `%` and the rest
of printable ASCII are fine.

`.` and `:` are the structural characters: `.` separates the segments a resource
type is built from and `:` separates a type from its id. Without the refusal, a
policy declaring `resource: "posts:<id>"` and a request whose id field carries
`1.member:2` resolves to `posts:1.member:2`, which the verifier reads as the
resource type `posts.member` — the decision is taken for a type the RPC was
never guarding, and the rule that should have gated it never runs.

The refusal happens during resolution, before any backend is called, because
every backend (o3co, OPA, Cedar, static rules) consumes the same resolved
string. It surfaces as `*interceptors.ResourceValueError`, which the gRPC and
ConnectRPC interceptors map to `PermissionDenied` — the request is denied, the
handler never runs, and the verifier is never asked.

**If your ids legitimately carry `.`, `:` or non-ASCII** — a DID, an email, a
dotted version — the request will now be denied where it used to be resolved.
Either percent-encode the value before it reaches the mapped request field
(percent-encoding round-trips through the grammar: `1%2Emember` stays one
segment), or configure a `ResourceParser` on the verifier written for your
syntax. A field mapping whose placeholder does **not** appear in the resource
template is not affected — those values are forwarded as request context, where
the resource grammar does not apply, so a `subscriber_did` mapping keeps working
unchanged.

Substitution is a single pass over the template: a value that itself spells
`<some-placeholder>` is left as data, never rewritten by another mapping.

[auth.policy-verifier]: https://github.com/o3co/auth.policy-verifier

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

### o3co endpoint options

| Option | Effect |
|---|---|
| `WithO3coTimeout(d)` | HTTP client timeout. Default `10s`. |
| `WithO3coMaxResponseBodySize(n)` | Cap on bytes read from the response body. Default 1 MiB. |
| `WithO3coLogLevel(level)` | Level for the endpoint's internal logger. Default `slog.LevelError`. |
| `WithO3coRequestIDHeaderKey(key)` | Header the request ID is forwarded in. Default `x-request-id`; `""` disables forwarding. |
| `WithO3coHeaders(map[string]string)` | Static headers added to every verify request. Merges across calls. |

`WithO3coHeaders` is what a deployment needs when auth.policy-verifier has its
optional `http.callerAuth` gate turned on. That gate expects a shared credential
in a header of its own (`x-caller-token` by default) and answers a different
question from the subject bearer token: *which service* may ask for a decision
at all. Without a way to send it, enabling the gate rejects every Go enforcement
point with `401 caller_unauthenticated`.

```go
verifier, err := endpoint.NewO3coEndpoint(
    "http://localhost:3000",
    endpoint.WithO3coHeaders(map[string]string{
        "x-caller-token": os.Getenv("VERIFIER_CALLER_TOKEN"),
    }),
)
```

The headers the endpoint sets itself cannot be overridden here — `Content-Type`,
`Accept`, `Authorization` and the configured request-ID header. `NewO3coEndpoint`
returns an error rather than letting a static header quietly replace the subject
token. (Disabling request-ID forwarding releases that one, since the endpoint
then no longer sets it.)

All backends implement the `endpoint.VerifierEndpoint` interface:

```go
type VerifierEndpoint interface {
    Verify(ctx context.Context, resource, action string) error
}
```

Bearer token and request ID are passed via `context.Context`, set by the framework-specific `VerificationInterceptor`.

## Streaming

A stream is authorized **before its handler is invoked**, on both frameworks —
a bidirectional or client-streaming handler that sends before it receives, or a
server-streaming handler that never receives at all, is checked like any other.

On gRPC the check is then repeated on each `RecvMsg`. The resource and action
are fixed for the life of a stream, so that re-check is not a second opinion on
the same question: it is what stops delivery on a long-lived stream whose grant
has been revoked, or whose token expired, since the stream opened.

`field_mappings` are not supported for streaming RPCs — there is no single
request message to resolve them from — and a streaming method that declares one
fails with `Internal`.

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
