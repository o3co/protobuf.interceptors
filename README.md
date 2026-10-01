# protobuf.interceptors

Last updated: 2026-10-01

[日本語](README.ja.md)

[![CI](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/protobuf.interceptors/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/o3co/protobuf.interceptors/graph/badge.svg)](https://codecov.io/gh/o3co/protobuf.interceptors)
[![Go Reference](https://pkg.go.dev/badge/github.com/o3co/protobuf.interceptors.svg)](https://pkg.go.dev/github.com/o3co/protobuf.interceptors)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> This repository handles **authorization enforcement** (gRPC / ConnectRPC) in the three-layer separation of concerns ([authentication & token issuance](https://github.com/o3co/auth.provider) / [authorization decision](https://github.com/o3co/auth.policy-verifier) / authorization enforcement) of the [auth](https://github.com/o3co/auth) stack — delegating the allow/deny decision to auth.policy-verifier, OPA, Cedar, or any other `VerifierEndpoint`.

Framework-agnostic protobuf method option authorization interceptors for Go. Declares access policy (resource + action) in `.proto` method options and enforces it at runtime via pluggable verification backends. Supports both gRPC and ConnectRPC.

## Responsibility

**Role.** This library is the enforcement layer of the auth stack, inside a Go
service, in front of its gRPC or ConnectRPC handlers. Authentication and token
issuance belong to [auth.provider](https://github.com/o3co/auth.provider); the
authorization decision belongs to a backend —
[auth.policy-verifier](https://github.com/o3co/auth.policy-verifier), OPA, a
Cedar agent, or any `VerifierEndpoint` of your own. This library asks the
backend and carries out its answer.

**It owns:**

- reading the policy a method declares in its `.proto` options, and resolving
  the resource and action from the request, refusing a request value that
  would change which resource is named;
- reading the bearer token and request ID from the request, refusing a
  malformed credential, and passing both to the backend;
- asking the backend before the handler runs — and on each message a stream
  receives — and refusing the RPC unless it allows;
- telling the caller the outcome as a status code with a fixed message, and
  handing the service the full error and the decision behind it;
- the HTTP clients for the built-in backends: plaintext only to loopback, no
  redirects, bounded reads, and a strict reading of each backend's answer.

**It does not:**

- **authenticate.** It checks only the shape of the `authorization` value; it
  never verifies a token's signature, expiry, issuer or audience. That is the
  backend's job (the o3co and OPA endpoints send the token to the backend) or,
  for Cedar, the principal resolver you supply.
- **decide.** No policy is evaluated here. The static endpoint matches a fixed
  list of resource and action patterns you supply, and nothing more.
- **record.** The interceptors write no logs of their own; the decision goes
  to your handler and observer (see [Recording the decision](#recording-the-decision)).
- secure the server's own transport, or limit request rates.

The framework interceptors are separate modules so that a gRPC service does not
depend on ConnectRPC, and a ConnectRPC service not on grpc-go (see
[Modules](#modules)).

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
│                                  │  stores PolicyData{Resource, Action} in ctx
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  VerificationInterceptor         │  reads policy from ctx,
│                                  │  calls VerifierEndpoint.Verify(),
│                                  │  refuses with PermissionDenied,
│                                  │  Unauthenticated or Internal
└───────────────┬──────────────────┘
                │
                ▼
          handler (your code)
```

### Which methods are checked

The policy is read from the method's descriptor in the protobuf registry:

- **Descriptor found, policy option set** — the RPC is checked.
- **Descriptor found, no policy option** — the RPC is not checked and passes
  through. On grpc-go, the health and reflection services
  (`google.golang.org/grpc/health`, `google.golang.org/grpc/reflection`) are
  such methods.
- **No descriptor** — the RPC is **refused** with `Internal` before its handler
  runs, since its policy cannot be known. On gRPC that is a method missing from
  `protoregistry.GlobalFiles`: one served by `grpc.UnknownServiceHandler`, by a
  hand-written `ServiceDesc` whose `.proto` was never registered, or by a
  gogo/protobuf-generated service, whose descriptors are registered with gogo's
  registry rather than `GlobalFiles`. On ConnectRPC it is a handler built
  without `connect.WithSchema`: hand-built handlers, code from a
  protoc-gen-connect-go too old to emit `connect.WithSchema`, and ConnectRPC's
  own `connectrpc.com/grpchealth` and `connectrpc.com/grpcreflect` handlers,
  which set no schema. Mount those without these interceptors (see
  [ConnectRPC](#connectrpc)).

Server reflection publishes method options, so a client that can reach the
reflection service can read every method's policy option: its resource
template, action and field mappings.

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
ConnectRPC interceptors map to `PermissionDenied` with the fixed message
`access denied` — the request is denied, the handler never runs, and the
verifier is never asked. Which placeholder and character were refused is not
sent to the caller; see [Errors](#errors) for where it can be read.

**If your ids legitimately carry `.`, `:` or non-ASCII** — a DID, an email, a
dotted version, a non-Latin id — the request is denied. Three remedies work on
every framework; which one fits depends on the backend:

- **Percent-encode the value before it reaches the mapped request field.**
  Percent-encoding round-trips through the grammar (`1%2Emember` stays one
  segment) and `%` is itself accepted, so the verifier can decode it back; on
  another backend, the policies are written for the encoded form.
- **Configure a `ResourceParser` on the verifier** written for your id syntax,
  and encode to that syntax at the call site. This one needs auth.policy-verifier
  (the o3co endpoint).
- **Restructure the policy so the offending value is never substituted into the
  resource.** Guard the type the RPC actually owns (`resource: "subscriptions"`,
  `action: "read"`) and let the backend decide against the identity it already
  holds from the bearer token, instead of naming a DID in the resource string.
  The verifier, OPA and Cedar see the token; the static endpoint matches
  resource and action only, so it cannot make that decision.

A fourth path — keeping the field mapping but dropping its placeholder from the
resource template, so the value travels as request context instead — is **not
portable**: it works on ConnectRPC with the o3co endpoint and nowhere else. Read
[Extracted field forwarding](#extracted-field-forwarding) before relying on it.

Substitution is a single pass over the template: a value that itself spells
`<some-placeholder>` is left as data, never rewritten by another mapping.

Every `<name>` in the template must have a field mapping. One that has none — a
misspelled placeholder, or a mapping removed while the template kept it — fails
resolution with `Internal`, rather than reaching the backend as literal text
naming a resource no policy meant.

### Request fields a placeholder can read

`request_field` names a **top-level** field of the request message by its
`.proto` field name; a dotted path into a nested message is not read. The field
must be a single value (not `repeated`, not a `map`) of one of these kinds:

| Kind | Substituted as |
|---|---|
| `string` | the value as is |
| `int32`, `sint32`, `sfixed32`, `int64`, `sint64`, `sfixed64` | decimal, with `-` when negative |
| `uint32`, `uint64`, `fixed32`, `fixed64` | decimal |
| `bool` | `true` or `false` |
| `bytes` | lowercase hex |

Any other kind — `enum`, `float`, `double`, a message — and a field the message
does not have fail resolution with `Internal`. A field the request did not set
resolves to its default value, in proto3 the zero value: `0` and `false` fill
the placeholder, while an empty `string` or `bytes` is refused as empty.

A `bytes` field is substituted as its lowercase hex encoding, always: the byte
`0xff` resolves to `ff` and the two bytes `"ff"` to `6666`, so two different
values never name the same resource.

### Extracted field forwarding

`ResolveResourceWithFields` extracts **every** `field_mappings` entry, including
one whose placeholder never appears in the resource template. Such a value is
never substituted, so the segment grammar above never applies to it — a DID,
which is all colons, extracts without complaint. Whether it then reaches the
authorization decision depends on the framework *and* on the backend:

| Path | Extracted | Placed in context | Reaches the decision |
|---|---|---|---|
| ConnectRPC unary | yes | yes | only via the **o3co** endpoint |
| ConnectRPC streaming | — | — | no — `field_mappings` refused with `Internal` |
| gRPC unary | yes | **no, discarded** | **no** |
| gRPC streaming | — | — | no — `field_mappings` refused with `Internal` |

Only `connectrpc.PolicyOptionInterceptor` resolves with
`ResolveResourceWithFields` and attaches the result via
`interceptors.WithExtractedFields`. The gRPC unary interceptor resolves with
`ResolveResource`, which drops the fields; both stream interceptors refuse a
policy carrying `field_mappings` before resolving anything (see
[Streaming](#streaming)). And of the four backends only `endpoint.NewO3coEndpoint`
reads the context back out, sending it as the `context` object of `POST /verify`
— OPA, Cedar and the static endpoint never look at it.

**So on gRPC unary, moving a placeholder out of the resource template does not
make its value available to the decision — it removes it**: resolution no
longer refuses the value, but the verifier decides without it, a question with
less information than before, which is worse than a refusal. (A gRPC stream
whose policy keeps the mapping still fails with `Internal`; see
[Streaming](#streaming).) Use one of the remedies above that your backend
supports.

The gRPC unary path does not forward the values as ConnectRPC does. The stream
interceptors' refusal of `field_mappings` is a separate limitation, on either
framework: the policy interceptor runs before the handler reads any request
message, and a client or bidirectional stream has no single one.

[auth.policy-verifier]: https://github.com/o3co/auth.policy-verifier

## Modules

Three Go modules, each versioned and released on its own (see
[Versioning and releases](#versioning-and-releases)):

| Module | Import Path | What your build compiles |
|---|---|---|
| Core | `github.com/o3co/protobuf.interceptors` | `google.golang.org/protobuf` + stdlib |
| gRPC | `github.com/o3co/protobuf.interceptors/grpc` | core + `google.golang.org/grpc` |
| ConnectRPC | `github.com/o3co/protobuf.interceptors/connectrpc` | core + `connectrpc.com/connect` |

The core module contains the proto schema, context helpers, error types, resource resolution, and all verification backends. The framework-specific modules provide only the interceptor implementations.

The core's `go.mod` also requires `google.golang.org/grpc` and
`connectrpc.com/connect`: the test service its own tests and both framework
modules' tests share, under `testproto/`, is part of the core module. No other
core package imports either, so they join your module graph but are compiled
only if you import them.

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

// The Cedar agent authenticates nothing: the resolver verifies the bearer
// token and names the principal it stands for.
verifier, _ := endpoint.NewCedarEndpoint("http://localhost:8180",
    endpoint.WithCedarPrincipalResolver(func(ctx context.Context, token string) (string, error) {
        claims, err := verifyJWT(ctx, token) // signature, expiry, issuer, audience
        if err != nil {
            return "", err
        }
        return claims.Subject, nil
    }),
)

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

`connectrpc.com/grpchealth` and `connectrpc.com/grpcreflect` build their
handlers without `connect.WithSchema`, so behind these interceptors every
health check and reflection request is refused with `Internal`. Pass the
interceptors to your service handlers only, not as one option shared by every
handler:

```go
// The service is checked.
mux.Handle(foopbconnect.NewFooServiceHandler(&fooServer{},
    connect.WithInterceptors(
        policyconnect.PolicyOptionInterceptor(),
        policyconnect.VerificationInterceptor(verifier),
    ),
))

// Health and reflection are mounted without the interceptors.
mux.Handle(grpchealth.NewHandler(grpchealth.NewStaticChecker(foopbconnect.FooServiceName)))
reflector := grpcreflect.NewStaticReflector(foopbconnect.FooServiceName)
mux.Handle(grpcreflect.NewHandlerV1(reflector))
mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
```

The interceptors guard handlers. Passed to a ConnectRPC client, both pass every
call through untouched.

### Bearer token and request ID

The verification interceptors read both from the request (gRPC metadata or
HTTP headers) and put them on the context the endpoint is called with:

- **Bearer token** — from `authorization`. A request that carries none has no
  token and is not refused by the interceptor: whether it may proceed is the
  endpoint's decision. Every endpoint in package `endpoint` refuses it as
  `UnauthenticatedError` without asking its backend; a `VerifierEndpoint` of
  your own may let it through. Otherwise it must carry exactly one value of the form `Bearer <token>`: the scheme is
  compared case-insensitively (RFC 9110 §11.1) and the token must be non-empty
  and free of Unicode whitespace (no RFC 6750 `b64token` contains any).
  Several values, another scheme, or an empty token are refused with
  `Unauthenticated` before any backend is asked, and the observer sees the
  refusal. A method with no policy is not checked: a well-formed token is still
  placed on its context, and a malformed credential is not refused.
- **Request ID** — from `x-request-id`. The one value sent is kept when it is
  1–128 characters of `A-Z a-z 0-9 - _ . : + / = #`, the shape
  auth.policy-verifier accepts. Otherwise — none, several, or one outside that
  shape — the interceptor generates one, `YYYYMMDDHHmmss_<16 hex digits>` (the
  UTC second and 8 random bytes). Both frameworks do the same, through
  `interceptors.InboundBearerToken` and `interceptors.InboundRequestID`.

### Errors

The caller is told the outcome in a status code and a fixed message, the same
on both frameworks. An endpoint's error can name the backend, the URL it
called, or why a token was refused, so none of its text reaches the caller:

| Cause | Code | Message |
|---|---|---|
| `*interceptors.DeniedError`, including a refused placeholder value | `PermissionDenied` | `access denied` |
| `*interceptors.UnauthenticatedError`, including an unreadable credential | `Unauthenticated` | `unauthenticated` |
| `context.Canceled`, when the RPC's own context was canceled | `Canceled` | `request canceled` |
| `context.DeadlineExceeded`, when the RPC's own deadline passed | `DeadlineExceeded` | `deadline exceeded` |
| anything else — a backend failure (including the endpoint's own HTTP timeout while the RPC is live), a method with no descriptor, a placeholder with no mapping, `field_mappings` on a stream, an interceptor chain out of order, `UnconfirmedRevisionError`, `ErrCallerUnauthenticated` | `Internal` | `authorization check failed` |

The full error goes to the `WithDecisionObserver` observer for every check
(see [Recording the decision](#recording-the-decision)). The error an
interceptor returns also unwraps to it, so an interceptor placed outside these
can `errors.As` / `errors.Is` it — that is where a policy lookup or resolution
failure, which no observer sees, can be logged. The interceptors write no logs
of their own.

## Verification Backends

The `endpoint` package provides four backends:

| Backend | Constructor | Protocol |
|---|---|---|
| OPA | `endpoint.NewOPAEndpoint(baseURL, policyPath)` | `POST /v1/data/{path}` |
| Cedar Agent | `endpoint.NewCedarEndpoint(baseURL, endpoint.WithCedarPrincipalResolver(fn))` | `POST /v1/is_authorized` |
| o3co policy-verifier | `endpoint.NewO3coEndpoint(baseURL)` | `POST /verify` |
| Static rules | `endpoint.NewStaticEndpoint(rules)` | Local evaluation |

**The Cedar endpoint does no authentication.** The Cedar agent decides for
whatever principal it is asked about, and is never shown the bearer token, so
`NewCedarEndpoint` requires `WithCedarPrincipalResolver`: a function that
verifies the token — for a JWT its signature, expiry, issuer and audience — and
returns the principal's id. A resolver that only decodes the token lets any
caller name any principal. An error or an empty id is an
`UnauthenticatedError`, and the agent is not asked. The id is escaped as a
Cedar string literal, so a quote or backslash in it cannot change the entity
it names.

A base URL names its scheme, `http` or `https`, and a host; one without either
is refused at construction rather than guessed at. An o3co or OPA request
carries the subject's bearer token, and a Cedar request the principal resolved
from it, so `http://` is accepted only to loopback — `localhost`, `127.0.0.0/8`, `::1` — unless the
endpoint is given `WithO3coAllowInsecure()`, `WithOPAAllowInsecure()` or
`WithCedarAllowInsecure()`. Anywhere else, use `https://`. `localhost` is
accepted by name, in any case, and resolves through `/etc/hosts` and DNS like
any other host; a literal address is accepted only as written in 127.0.0.0/8
or as `::1` (an IPv4-mapped `::ffff:127.x.y.z` included), so `localhost.`,
`foo.localhost`, `127.1`, `2130706433`, `0.0.0.0` and a zoned `::1%lo0` are
not loopback.

No HTTP backend follows a redirect: a `3xx` is an error, so the request and
the bearer token on it reach only the backend that was configured.

When the caller's context is cancelled or its deadline passes, an HTTP
endpoint's error wraps `ctx.Err()`, so `errors.Is` finds `context.Canceled` or
`context.DeadlineExceeded`. The endpoint's own timeout is the backend failing
to answer, and wraps neither.

For mutual TLS or a private CA, give the endpoint the transport to send over —
`WithO3coTransport(rt)`, `WithOPATransport(rt)` or `WithCedarTransport(rt)`,
for example an `*http.Transport` with its `TLSClientConfig` set. The endpoint's
timeout and its refusal to follow redirects still apply to a transport that
honours the request's context and does not follow redirects itself, as
`*http.Transport` does.

```go
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = &tls.Config{
    RootCAs:      privateCAs,
    Certificates: []tls.Certificate{clientCert},
}
verifier, err := endpoint.NewO3coEndpoint(
    "https://verifier.internal:3000",
    endpoint.WithO3coTransport(transport),
)
```

### o3co endpoint options

| Option | Effect |
|---|---|
| `WithO3coTimeout(d)` | HTTP client timeout. Default `10s`. Panics unless `d` is positive. |
| `WithO3coMaxResponseBodySize(n)` | Accepts a response body of up to `n` bytes; one more byte is read to detect a larger body, which is never read as an answer. Default 1 MiB. Panics unless `n` is positive. |
| `WithO3coLogLevel(level)` | Level for the endpoint's internal logger. Default `slog.LevelError`. |
| `WithO3coRequestIDHeaderKey(key)` | Header the request ID is forwarded in. Default `x-request-id`; `""` disables forwarding. Panics unless `key` is an RFC 7230 token other than `Authorization`, `Content-Type` and `Accept`; a key a `WithO3coHeaders` header also names makes `NewO3coEndpoint` return an error. The OPA and Cedar options check the same. |
| `WithO3coHeaders(map[string]string)` | Static headers added to every verify request. Merges across calls. |
| `WithO3coRequireConfirmedRevision()` | Refuse an allow not established against confirmed policy revisions. Off by default; see [Requiring a confirmed revision](#requiring-a-confirmed-revision). |
| `WithO3coAllowInsecure()` | Permit an `http://` base URL to a host other than loopback. |
| `WithO3coTransport(rt)` | Transport the requests are sent over, e.g. for mutual TLS. Default `http.DefaultTransport`. Panics if `rt` is nil. |

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
then does not set it.)

The verifier answers `401` both for a bad subject token and for a refused caller
credential. The endpoint tells them apart by the response's `code`: a
`caller_unauthenticated` refusal returns `endpoint.ErrCallerUnauthenticated`,
which the interceptors map to `Internal` — a missing or rotated caller token is
this service's fault, and the RPC caller must not be told its own token is
invalid. Every other `401` is still an `UnauthenticatedError`.

### OPA endpoint

`NewOPAEndpoint(baseURL, policyPath)` asks `POST {baseURL}/v1/data/{policyPath}`
with the input `{"resource", "action", "token"}` — the bearer token as sent, so
the policy must verify it. It allows only when the response's `result` key, in
exactly that case, holds JSON `true`. An absent `result` (OPA's undefined),
`null` or `false` is a deny; a `result` that is not a boolean, a body that is not a JSON
object, one larger than the size bound, and any non-`2xx` status are errors. An
empty `policyPath` is refused at construction.

| Option | Effect |
|---|---|
| `WithOPATimeout(d)` | HTTP client timeout. Default `10s`. Panics unless `d` is positive. |
| `WithOPAMaxResponseBodySize(n)` | Accepts a response body of up to `n` bytes; one more byte is read to detect a larger body, which is never read as an answer. Default 1 MiB. Panics unless `n` is positive. |
| `WithOPALogLevel(level)` | Level for the endpoint's internal logger. Default `slog.LevelError`. |
| `WithOPARequestIDHeaderKey(key)` | Header the request ID is forwarded in. Default `x-request-id`; `""` disables forwarding. Panics unless `key` is an RFC 7230 token other than `Authorization`, `Content-Type` and `Accept`. |
| `WithOPAAllowInsecure()` | Permit an `http://` base URL to a host other than loopback. |
| `WithOPATransport(rt)` | Transport the requests are sent over, e.g. for mutual TLS. Default `http.DefaultTransport`. Panics if `rt` is nil. |

### Cedar endpoint

`NewCedarEndpoint(baseURL, opts...)` asks `POST {baseURL}/v1/is_authorized`
with the principal the resolver returned, the action and the resource, each as
a Cedar entity UID (`User::"alice"`, `Action::"read"`, `Resource::"posts/1"`
with the default prefixes), and an empty context. It allows only when the
response's `decision` key, in exactly that case, is `"Allow"`; any other
decision is a deny, and a body that is not a JSON object, one larger than the
size bound, and any non-`2xx` status are errors. Without
`WithCedarPrincipalResolver` the constructor returns an error.

| Option | Effect |
|---|---|
| `WithCedarPrincipalResolver(fn)` | **Required.** Verifies the bearer token and returns the principal's id; see above. Panics if `fn` is nil. |
| `WithCedarPrincipalPrefix(prefix)` | Entity type of the principal. Default `User`. |
| `WithCedarActionPrefix(prefix)` | Entity type of the action. Default `Action`. |
| `WithCedarResourcePrefix(prefix)` | Entity type of the resource. Default `Resource`. |
| `WithCedarTimeout(d)` | HTTP client timeout. Default `10s`. Panics unless `d` is positive. |
| `WithCedarMaxResponseBodySize(n)` | Accepts a response body of up to `n` bytes; one more byte is read to detect a larger body, which is never read as an answer. Default 1 MiB. Panics unless `n` is positive. |
| `WithCedarLogLevel(level)` | Level for the endpoint's internal logger. Default `slog.LevelError`. |
| `WithCedarRequestIDHeaderKey(key)` | Header the request ID is forwarded in. Default `x-request-id`; `""` disables forwarding. Panics unless `key` is an RFC 7230 token other than `Authorization`, `Content-Type` and `Accept`. |
| `WithCedarAllowInsecure()` | Permit an `http://` base URL to a host other than loopback. |
| `WithCedarTransport(rt)` | Transport the requests are sent over, e.g. for mutual TLS. Default `http.DefaultTransport`. Panics if `rt` is nil. |

### Static endpoint

`NewStaticEndpoint(rules)` decides locally, against a fixed list of
`StaticRule{Resource, Action}`: the request is allowed when one rule matches
both. A pattern is matched exactly, `*` matches anything, and a pattern ending
in `*` matches by prefix (`posts/*` matches `posts/1`). It still requires a
bearer token on the context, and checks nothing else about it.

### The endpoint interface

All backends implement [`endpoint.VerifierEndpoint`](endpoint/endpoint.go): a
`Verify` given the context, the resolved resource and the action, whose error
is the verdict — `nil` allows, `*interceptors.DeniedError` denies,
`*interceptors.UnauthenticatedError` refuses the credential, and anything else
is a failure to decide. An endpoint that can also report the decision behind
its verdict implements `endpoint.DecisionVerifier`.

Bearer token and request ID are passed via `context.Context`, set by the
framework-specific `VerificationInterceptor` (see
[Bearer token and request ID](#bearer-token-and-request-id)).

The interface carries only the resolved resource and action, so anything else an
endpoint wants must come off the context itself. Each built-in endpoint reads
the bearer token there, and uses it its own way: the o3co endpoint sends it to
the verifier, the OPA endpoint sends it as `input.token`, the Cedar endpoint
resolves a principal from it, and the static endpoint only requires one. Only
the o3co endpoint reads the extracted `field_mappings` values, forwarding them
as the `context` object of `POST /verify` when a framework put them there; OPA
decides on resource, action and token, Cedar on principal, action and
resource, and the static endpoint matches resource and action — see
[Extracted field forwarding](#extracted-field-forwarding).

## Recording the decision

A service that must record *why* an operation was allowed or denied — which
rule decided, and which policy revision — gets the verifier's decision without
parsing HTTP. Only the o3co endpoint reports one (it implements
`endpoint.DecisionVerifier`); OPA, Cedar, the static endpoint and any
`VerifierEndpoint` of your own report nothing, which reads as unknown.

**In the handler.** When an RPC is allowed, the decision is on the handler's
context. For a stream it is the decision that opened the stream:

```go
if d, ok := interceptors.DecisionFromContext(ctx); ok {
    record(d.RequestID, d.Groups) // alongside the operation it authorized
}
```

A group whose `Restricts` is set narrowed the allow and granted nothing: leave
it out where the record says what granted it. A verifier older than v0.16.0
marks no group, so there `Restricts` is false on every group and does not mean
the group granted.

**For every check, denials included.** A denied RPC's handler never runs, so
the verification interceptors also take an observer. It sees every check — on
streams, the opening check and each re-check of a received message, on both
frameworks — with the endpoint's error before it is mapped for the caller:

```go
observe := func(ctx context.Context, ev interceptors.DecisionEvent) {
    // ev.Resource, ev.Action; ev.Decision (nil when nothing was reported);
    // ev.Err (nil when allowed; errors.As finds *interceptors.DeniedError)
}
policygrpc.VerificationInterceptor(verifier, policygrpc.WithDecisionObserver(observe))
policyconnect.VerificationInterceptor(verifier, policyconnect.WithDecisionObserver(observe))
```

On a denial the decision is also on `DeniedError.Decision`, with the verifier's
deny `code` in `Decision.Code`.

**Nothing of it reaches the RPC caller.** Revisions and evaluation statuses say
when a policy set changed and whether a denial was the engine failing. The
caller still gets `PermissionDenied: access denied`, and no error this library
returns carries a decision in its message. No endpoint logs response
bodies at its default level either — the error line names the status, the
request ID and (o3co) the code, and the body is at `Debug`.

**What each rule reported.** A policy-backed rule's outcome carries an
`Evaluation`, but only when the verifier sets
`verify.evaluationInResponse = "include"`:

| Verifier sent | `RuleOutcome.Evaluation` | `ConfirmedRevision()` |
|---|---|---|
| `{ "status": "completed", "revision": "sha256:…" }` | `Status: EvaluationCompleted`, `Revision` set | the revision, `true` |
| `{ "status": "completed", "revision": null, "loadedRevision": "…" }` | `Status: EvaluationCompleted`, `Revision: ""`, `LoadedRevision` set | `false` — what ran is not established |
| `{ "status": "failed", … }` | `Status: EvaluationFailed` | `false` — the rule failed closed |
| `{ "status": "not_invoked" }` | `Status: EvaluationNotInvoked` | `false` — nothing was evaluated |
| no `evaluation` | `nil` | `false` — unknown |

The last row is what an older verifier, one that has not opted in, and a rule
with no policy source all send: absence means unknown, and all three look the
same. A completed evaluation may also name `DeterminingPolicies` — the permits
that applied to an allow, the forbids that applied to a deny.

The verifier's own advice on what to store applies here: for each operation, the
verdict, the deny code, the reason with each evaluation, and the request ID
that was sent (`Decision.RequestID`). Its `decision` log event carries the same
request ID, so the two records join on it. The verifier keeps an
`x-request-id` only if it is at most 128 characters of
`[A-Za-z0-9-_.:+/=#]`, and the interceptors carry an inbound ID only in that
shape, generating one otherwise, so the ID they send always joins.

An allow takes both the status and the body: a `200` whose body is a whole
decision envelope with `decision: "allow"`. A body that is empty, not JSON,
missing a key the verifier's contract requires, null or mistyped anywhere it
types a value, an allow carrying a deny's `code` or `message` (even as null),
larger than `WithO3coMaxResponseBodySize`, or cut off while
reading is not a decision and reports nothing. On a `200` that makes the answer
an error, not an allow, and so does any other `2xx` and a `200` carrying a
whole deny (which is still reported to the observer). The interceptors map that
error to `Internal`. A `403` is a deny whatever its body holds; the body only
reports why. Keys are matched as the contract spells them: one in another
case (`Passed`, `Decision`) is a key the contract does not define, and is
ignored like any other, so it cannot stand in for the key it resembles. The
exception is `restricts` in another case, which is refused rather than
ignored: the envelope is then not whole, and a `200` carrying it fails closed.
OPA's `result` and the Cedar agent's `decision` are likewise read only by
their exact key.

### Requiring a confirmed revision

`WithO3coRequireConfirmedRevision()` refuses an allow unless it is established
against confirmed revisions (`Decision.RevisionConfirmed()`). That means every
group passed, at least one of them grants, and the rule that satisfied each
granting group — its `satisfiedBy` — reports a completed evaluation with a
well-formed revision. Alternatives tried before the satisfying rule are not
consulted. A restricting group (`RuleGroup.Restricts`, the verifier's
`restricts: true` — a delegated token's range, for one) narrows what the
granting groups allow and grants nothing, so what satisfied it is not
consulted either, and an allow whose groups all restrict is refused. A
verifier older than v0.16.0 marks no group, so its restricting groups are
checked as granting ones and, having no policy source, refuse the allow. A
refused allow returns `*interceptors.UnconfirmedRevisionError`, which the
interceptors map to `Internal`: the verifier allowed, and the service could
not establish what that rests on. Denials are unaffected.

Against a verifier that has not set `evaluationInResponse = "include"`, this
refuses **every** allow. It also refuses any allow whose granting group a rule
without a policy source satisfied, so it suits deployments whose every
granting rule group is policy-backed. The verifier cannot say which it is
before a decision is requested, so this is not checked at construction.
Instead, the first refused allow whose response carried no evaluation at all
logs one error naming the setting.

## Streaming

A stream is authorized **before its handler is invoked**, on both frameworks —
a bidirectional or client-streaming handler that sends before it receives, or a
handler that never receives, is checked like any other.

The check is then repeated on each message the handler receives — `RecvMsg` on
gRPC, `Receive` on ConnectRPC. The resource and action are fixed for the life
of a stream, so that re-check is not a second opinion on the same question: it
is what stops a stream that keeps receiving once its grant has been revoked, or
its token expired, since the stream opened. It runs after the message arrives,
so a message that arrives after revocation is cleared and never handed to the
handler, which gets the mapped error instead, whatever codec decoded it. A
receive that fails — the client closed its side, the stream broke — has no
message and is not re-checked. Each received message costs one verifier call,
so a stream can also end partway when the verifier fails.

Sends are not re-checked, so a server-streaming RPC is checked before its
handler runs and again when the handler reads its one request, and never after
that.

`field_mappings` are not supported for streaming RPCs — the policy interceptor
runs before the handler reads any request message, and a client or
bidirectional stream has no single one — and a streaming method that declares one
fails with `Internal`, on both frameworks, before any resolution is attempted.
This is a standing limitation, independent of the placeholder-value rule: it
applies whether or not the values would have been accepted.
A streaming RPC that needs a per-message identity has to carry it in the message
and check it in the handler.

## Proto Schema

The policy option is defined in [`schema/policy.proto`](schema/policy.proto):
the `o3co.authz.v1.policy` extension of `google.protobuf.MethodOptions`, field
50000, holding a `Policy` — `resource`, `action` and repeated `field_mappings`,
each a `placeholder` and the `request_field` it is filled from. The generated
Go code is the `schema` package (Go package name `policy`).

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

// A DecisionVerifier, for testing what your handler or observer does with a decision.
deciding := endpointtest.Decide(func(ctx context.Context, resource, action string) (*interceptors.Decision, error) {
    return &interceptors.Decision{RequestID: "req-1"}, nil
})
```

## Development

The repository holds three modules, so run each check in each of `.`, `grpc/`
and `connectrpc/`. The framework modules build against the checkout's core
(`replace => ../`), so a core change is tested with both of them:

```sh
for dir in . grpc connectrpc; do
  (cd "$dir" && test -z "$(gofmt -l .)" && go vet ./... && go test ./... -race -count=1)
done
```

CI also runs gofmt, staticcheck and `go mod tidy -diff` on the minimum
toolchain (the `go` directive), and govulncheck on the latest stable one;
[AGENTS.md](AGENTS.md) lists the commands, how to regenerate the protobuf code,
and the rules a change follows.

### Wire contract tests

The o3co endpoint is tested against auth.policy-verifier's wire contract as the
verifier publishes it, in
[`tests/integration/src/conformance/fixtures/wireContract`](https://github.com/o3co/auth.policy-verifier/tree/develop/tests/integration/src/conformance/fixtures/wireContract),
rather than against a copy of it. CI checks the verifier out at the release
pinned in `.github/workflows/wire-contract.yml`. To run the tests locally, point
`O3CO_VERIFIER_WIRE_CONTRACT` at that directory in a checkout; without it they
are skipped:

```sh
O3CO_VERIFIER_WIRE_CONTRACT=../auth.policy-verifier/tests/integration/src/conformance/fixtures/wireContract \
  go test ./... -run WireContract
```

## Versioning and releases

Each module has its own version and its own tags:

| Module | Tags | Install |
|---|---|---|
| Core | `vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors@vX.Y.Z` |
| gRPC | `grpc/vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors/grpc@vX.Y.Z` |
| ConnectRPC | `connectrpc/vX.Y.Z` | `go get github.com/o3co/protobuf.interceptors/connectrpc@vX.Y.Z` |

- **The version numbers are independent.** `grpc/v0.4.0` and `v0.4.0` are
  different releases of different modules; a framework module's version says
  nothing about the core's.
- **A framework module requires the core release it was released against**, the
  newest at that time. `go get` of the framework module brings that core
  version in, or a newer one if your module requires it.
- **While the major version is `0`, a minor release may break the API**; a
  patch release does not. Read the release notes before raising a minor.
- **Release notes** are the [GitHub Releases](https://github.com/o3co/protobuf.interceptors/releases),
  one per tag; there is no CHANGELOG.
- **Retracted versions** — `grpc/v0.1.0`, `connectrpc/v0.1.0` and
  `connectrpc/v0.2.0` require a core version that does not exist, so they
  cannot be built or required. `go get` stops selecting a retracted version,
  and warns where one is required, once the module's next release (not a
  prerelease), which carries the retraction, is published.

## License

Apache License 2.0. See [LICENSE](LICENSE).
