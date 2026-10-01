# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## Comments

- **A comment states what holds now**: an invariant, a constraint, a security reason, an external specification (`RFC 6750 §2.1`). It does not paraphrase the code.
- **No history in comments.** No issue or pull request numbers, no design or review labels, no phases, nothing of the form "previously …" or "fixed in …". History belongs in commits, issues and the GitHub Release notes.
- Generated code (`*.pb.go`, `testproto/testpbconnect/`) is never edited by hand; change the `.proto` and regenerate (see [Tooling](#tooling)).

## README Files

`README.md` is for the people who use the library: what it does, where it sits in the auth stack, how to install, configure and run it. `README.ja.md` carries the same facts in Japanese; a change to one is made to the other in the same pull request.

- **A last-updated date is required**, on the line directly under the H1 title: `Last updated: YYYY-MM-DD` (`最終更新: YYYY-MM-DD` in `README.ja.md`). Update it whenever you change the README.
- **Responsibility and role are required**, in a `## Responsibility` section (`## 責務と役割` in Japanese) near the top: what the library is for and where it sits, what it owns and what it does not.
- **Refer to code by file name, never by line number.** Line numbers drift with every edit.
- **Link definitions instead of copying them.** A copied type, signature or message drifts from the code.
- When a change alters what a caller sees — a status code, a message, an option, a refusal — update the README in the same pull request. When it alters what a file does, update that file's doc comments.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

## Branches

The default branch is `develop`, and pull requests target it. There is no `main`. Releases are tagged on `develop` (see [Release Process](#release-process)).

## Project Layout

The repository holds three Go modules:

| Module | Directory | Packages |
| --- | --- | --- |
| `github.com/o3co/protobuf.interceptors` (core) | `/` | `interceptors` (resolution, inbound credentials, errors, decisions, context plumbing), `endpoint` (the backends), `endpointtest` (mocks for consumers' tests), `schema` (the generated policy option), `internal`, `testproto` (the test service shared by every module's tests) |
| `github.com/o3co/protobuf.interceptors/grpc` | `grpc/` | the grpc-go interceptors |
| `github.com/o3co/protobuf.interceptors/connectrpc` | `connectrpc/` | the ConnectRPC interceptors |

- **Dependencies point one way**: the framework modules depend on the core; the core never imports them. Inside the core, `endpoint` depends on the root package, never the reverse. What the two framework modules share — resolution, credential parsing, the error types — lives in the core, so the two cannot drift; what is framework-specific stays in its module.
- **The framework modules build against the checkout's core.** Each `go.mod` has `replace github.com/o3co/protobuf.interceptors => ../`, so a change to the core and its use in a framework module land in one pull request and are tested together. Its `require` names a **published** core version, and that is what a consumer gets: a `replace` applies only in the module where it is written. So the `require` must name a core version that has every API the module uses. Between a core change and the next core release it does not; `release.yml` refuses to release a framework module until it does (see [Release Process](#release-process)).
- **`testproto/` is in the core module** so the core and both framework modules test against one service. That is why the core's `go.mod` requires `google.golang.org/grpc` and `connectrpc.com/connect`; no other core package imports either, so a consumer that imports only the core compiles neither.

## Wire Contract with auth.policy-verifier

The o3co endpoint (`endpoint/o3co.go`, `endpoint/o3co_decision.go`) asks auth.policy-verifier `POST /verify`. What its answers mean:

| Answer | Result |
| --- | --- |
| `200` with a whole decision envelope whose `decision` is `"allow"` and which has no `code` or `message` key, not even as `null` | allow |
| `200` with anything else — an empty body, not JSON, not a whole envelope, a whole deny, larger than `WithO3coMaxResponseBodySize`, cut off while reading | error (a whole deny is still returned as the decision, so the observer sees it) |
| any other `2xx` | error |
| `403` | `*interceptors.DeniedError`, whatever the body holds; a whole envelope only reports why |
| `401` whose body is a whole error envelope with `code` `"caller_unauthenticated"` | `endpoint.ErrCallerUnauthenticated`: the verifier refused this service's caller credential, not the subject's token |
| any other `401` | `*interceptors.UnauthenticatedError` |
| anything else, `3xx` included (no redirect is followed) | error |

- **A whole envelope** has every key the contract requires of its kind, none `null` where the contract types a value, each of the right type. A body that is not one reports nothing: the decision is `nil`.
- **Keys are case-sensitive.** A key in another case is one the contract does not define and is ignored like any other unknown key — except `restricts` in another case, which makes the rule group, and so the envelope, not whole. `restricts`, when present, must be `true`. `satisfiedBy` is present exactly on a passing group.
- **Evaluations**: `status` is required; `completed` and `failed` carry `revision` (a string, or `null` for unknown); `loadedRevision`, `determiningPolicies` and `determiningPoliciesOmitted` are optional and never `null`. A status this library does not know is passed through.
- **Restricting groups** (`RuleGroup.Restricts`) grant nothing: `Decision.RevisionConfirmed` skips them, and an allow whose groups all restrict is never confirmed.
- **The request ID** is kept from the inbound request only in the shape the verifier accepts (`request.go`), so the ID sent always joins the verifier's record.

The tests hold the code to the verifier's own statement of the contract, `tests/integration/src/conformance/fixtures/wireContract` in auth.policy-verifier, rather than to a copy: `endpoint/wirecontract_test.go`, `revision_contract_test.go` and `request_id_test.go`, through `internal/wirecontract`. They read the directory named by `O3CO_VERIFIER_WIRE_CONTRACT` and are skipped when it is unset:

```sh
O3CO_VERIFIER_WIRE_CONTRACT=<auth.policy-verifier checkout>/tests/integration/src/conformance/fixtures/wireContract \
  go test ./... -run WireContract
```

`.github/workflows/wire-contract.yml` checks the verifier out at the release pinned in its `VERIFIER_RELEASE`, fails if any contract test is skipped, and weekly also runs against the verifier's `develop`, so a contract change surfaces before the pin moves. When the verifier releases a contract change, **the pull request that follows it moves `VERIFIER_RELEASE`**. A verifier change to what a status means, to the envelope's required keys, or to a code this library reads reaches this repository; a new deny code does not.

## Error Mapping

`grpc/errors.go` and `connectrpc/errors.go` map an error to what the RPC caller is told. The two are the same table, in each framework's vocabulary:

| Error | Code | Message |
| --- | --- | --- |
| `*interceptors.DeniedError`, including a refused placeholder value (`*interceptors.ResourceValueError` unwraps to one) | `PermissionDenied` | `access denied` |
| `*interceptors.UnauthenticatedError` | `Unauthenticated` | `unauthenticated` |
| `context.Canceled`, when the RPC's own context was canceled | `Canceled` | `request canceled` |
| `context.DeadlineExceeded`, when the RPC's own deadline passed | `DeadlineExceeded` | `deadline exceeded` |
| anything else | `Internal` | `authorization check failed` |

- **The message is fixed per code.** An endpoint's error can name the backend, the URL it called or why a token was refused, so none of its text reaches the caller, and no error carries a decision in its message.
- **`Canceled` and `DeadlineExceeded` need the RPC's context to have ended.** An endpoint whose own timeout fired, or that was canceled while the RPC was live, failed: that is `Internal`. The HTTP endpoints wrap `ctx.Err()` only when the caller's context ended (`endpoint/http.go`), so the two cannot be confused.
- **The returned error unwraps to the cause**, so an interceptor outside these can `errors.As` / `errors.Is` it. The observer gets the cause before mapping.
- **An error the table does not name is `Internal`, and no error lets the handler run.**
- A change to one framework's mapping is a change to both, and to the README's [Errors](README.md#errors) table. `grpc/errors_test.go` and `connectrpc/errors_test.go` pin the table.

## Fail-Closed Rules

The interceptors refuse rather than guess. Each rule holds on both frameworks:

- **A method with no descriptor is refused** with `Internal` before its handler runs, since its policy cannot be known: on gRPC, a method missing from `protoregistry.GlobalFiles`; on ConnectRPC, a handler built without `connect.WithSchema`. A descriptor without the policy option is a method with no policy, and passes through. The gRPC interceptors cache only methods they found, so the cache is bounded by the registered methods however many names callers send.
- **The verification interceptor refuses an RPC the policy interceptor did not mark** (`MarkInterceptorRan`), so a chain with the policy interceptor missing or out of order fails instead of passing every RPC as unchecked.
- **A placeholder with no field mapping is refused** (`Internal`), and so is a mapped value that is empty or carries a character outside the verifier's segment token (`PermissionDenied`, no backend asked). See `resolve.go`.
- **`field_mappings` on a streaming method are refused** (`Internal`): no single request message exists when the stream opens.
- **A stream is checked before its handler runs, and re-checked after each message it receives.** A message that fails the re-check is cleared and never handed to the handler. A failed receive has no message and is not re-checked; sends are not re-checked.
- **A malformed credential is refused** with `Unauthenticated` before any backend is asked: several `authorization` values, another scheme, an empty token, or whitespace in the token. A method with no policy is not checked, so it is not refused there.
- **The HTTP endpoints** send plaintext only to loopback unless the `With…AllowInsecure` option is given, follow no redirect, and read at most the configured body size. An option given invalid input panics at the call (a programmer error); a constructor given an unusable URL or configuration returns an error.

## Release Process

Each module is versioned and released on its own, by a tag on `develop`:

| Module | Tag |
| --- | --- |
| core | `vX.Y.Z` |
| gRPC | `grpc/vX.Y.Z` |
| ConnectRPC | `connectrpc/vX.Y.Z` |

### Flow

A release that changes the core takes two stages, because the framework modules' `require` must name the published core:

1. Tag the core on `develop`: `git tag vX.Y.Z && git push origin vX.Y.Z`.
2. In a pull request, raise the framework modules' requirement: `go mod edit -require=github.com/o3co/protobuf.interceptors@vX.Y.Z && go mod tidy` in `grpc/` and `connectrpc/`. Merge it.
3. Tag the framework modules on that merge commit: `grpc/vA.B.C` and `connectrpc/vD.E.F`.

A framework module released without a core change skips stages 1 and 2, as long as it already requires the newest core release.

`.github/workflows/release.yml` runs on each tag. It reads the module and version from the tag, refuses a version that is not `v` + SemVer without build metadata or whose major would need a `/vN` module path, and vets and tests the module. For a framework module it also refuses a `go.mod` that does not require the newest core release (the newest full release for a full release), then drops the `replace` and builds, vets and tests against the published core — what a consumer gets. It then creates the GitHub Release with generated notes (a prerelease for a version with a `-` suffix) and asks `proxy.golang.org` for the version.

### Rules

- **There is no CHANGELOG.** The GitHub Release notes are the record. Pull request titles follow Conventional Commits, with `!` on a breaking change, so the generated notes show it.
- **While the major version is `0`, a breaking change bumps the minor** (`v0.4.x` → `v0.5.0`), never the patch; a feature bumps the minor; a fix alone bumps the patch.
- **A published version is permanent**: the module proxy serves it once fetched, whatever happens to the tag. A broken one is not deleted but retracted, with a `retract` directive and a rationale comment in that module's `go.mod`; the retraction takes effect when the module's next version is published.
- **Agents never push a tag without the user's explicit approval.** Propose the tag commands, and after a tag is pushed, watch the run (`gh run list --workflow=release.yml`, `gh run watch`).

## Tooling

### Tests and checks

CI (`.github/workflows/ci.yml`) runs, for each module:

- `go vet ./...` and `go test ./... -race -covermode=atomic -coverprofile=cover.out` on three toolchains: `minimum` (the `go` directive, the oldest a consumer may build with), `oldstable` and `stable` (the two releases the Go team supports). The `go` directive need not rise for the library to be tested on a supported Go.
- on the `minimum` toolchain only: `gofmt -l .` must print nothing, `go mod tidy -diff` must show nothing, staticcheck (pinned to `2025.1.1`) must report nothing, and the coverage report is uploaded to Codecov under the module's flag (`codecov.yml`).

The same locally, in each of `.`, `grpc/` and `connectrpc/`:

```sh
gofmt -l .
go vet ./...
go test ./... -race -count=1
go mod tidy -diff
go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

`.github/workflows/govulncheck.yml` scans each module on push, pull request and weekly, on the `stable` toolchain: the scan is of the module's own dependency graph, and standard library findings belong to whichever toolchain a consumer builds with.

### Regenerating protobuf code

`schema/policy.pb.go` is generated with protoc 34.0 and `protoc-gen-go` v1.36.10. CI's `proto-sync` job regenerates it and fails on any difference:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
make -C schema generate
```

`testproto/` is generated with protoc 34.0, `protoc-gen-go` v1.36.10, `protoc-gen-go-grpc` v1.6.0 and `protoc-gen-connect-go` v1.21.0. CI does not check it, so regenerate it whenever `testproto/test_service.proto` or one of these versions changes:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.0
cd testproto && protoc -I . -I ../schema \
  --go_out=paths=source_relative:. \
  --go-grpc_out=paths=source_relative:. \
  --connect-go_out=paths=source_relative:. \
  test_service.proto
```

The generators copy a `.proto` file's leading comments, its license header included, into the code they generate.
