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
| `WithO3coTimeout(d)` | HTTP client timeout. Default `10s`. |
| `WithO3coMaxResponseBodySize(n)` | Cap on bytes read from the response body. Default 1 MiB. |
| `WithO3coLogLevel(level)` | Level for the endpoint's internal logger. Default `slog.LevelError`. |
| `WithO3coRequestIDHeaderKey(key)` | Header the request ID is forwarded in. Default `x-request-id`; `""` disables forwarding. Panics unless `key` is an RFC 7230 token other than `Authorization`, `Content-Type` and `Accept`; a key a `WithO3coHeaders` header also names makes `NewO3coEndpoint` return an error. The OPA and Cedar options check the same. |
| `WithO3coHeaders(map[string]string)` | Static headers added to every verify request. Merges across calls. |
| `WithO3coRequireConfirmedRevision()` | Refuse an allow not established against confirmed policy revisions. Off by default; see [Requiring a confirmed revision](#requiring-a-confirmed-revision). |
| `WithO3coAllowInsecure()` | Permit an `http://` base URL to a host other than loopback. |
| `WithO3coTransport(rt)` | Transport the requests are sent over, e.g. for mutual TLS. Default `http.DefaultTransport`. |

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

All backends implement the `endpoint.VerifierEndpoint` interface:

```go
type VerifierEndpoint interface {
    Verify(ctx context.Context, resource, action string) error
}
```

Bearer token and request ID are passed via `context.Context`, set by the framework-specific `VerificationInterceptor`.

The interface carries only the resolved resource and action, so anything else an
endpoint wants must come off the context itself. Only the o3co endpoint does:
it forwards the extracted `field_mappings` values as the `context` object of
`POST /verify`, when a framework put them there. OPA, Cedar and the static
endpoint decide on resource and action alone — see
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
gRPC streams, the opening check and each `RecvMsg` re-check — with the
endpoint's error before it is mapped for the caller:

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
`[A-Za-z0-9-_.:+/=#]`; an ID outside that shape reaches it as none, and joins
nothing.

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

On gRPC the check is then repeated on each `RecvMsg`. The resource and action
are fixed for the life of a stream, so that re-check is not a second opinion on
the same question: it is what stops a stream that keeps receiving once its grant
has been revoked, or its token expired, since the stream opened. Sends are not
re-checked, so a server-streaming RPC is checked before its handler runs and
again when the generated handler reads its one request, and never after that.

`field_mappings` are not supported for streaming RPCs — the policy interceptor
runs before the handler reads any request message, and a client or
bidirectional stream has no single one — and a streaming method that declares one
fails with `Internal`, on both frameworks, before any resolution is attempted.
This is a standing limitation, independent of the placeholder-value rule: it
applies whether or not the values would have been accepted.
A streaming RPC that needs a per-message identity has to carry it in the message
and check it in the handler.

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

// A DecisionVerifier, for testing what your handler or observer does with a decision.
deciding := endpointtest.Decide(func(ctx context.Context, resource, action string) (*interceptors.Decision, error) {
    return &interceptors.Decision{RequestID: "req-1"}, nil
})
```

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

## License

Apache License 2.0. See [LICENSE](LICENSE).
