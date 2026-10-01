# Security Policy

## Reporting a vulnerability

Report a vulnerability privately, through GitHub's security advisories:
[open a draft advisory](https://github.com/o3co/protobuf.interceptors/security/advisories/new)
for `o3co/protobuf.interceptors`. Do not open a public issue or pull request
for it.

Include what you can of:

- the module and version affected (`github.com/o3co/protobuf.interceptors`,
  `/grpc` or `/connectrpc`, and the tag);
- the framework and backend involved (gRPC or ConnectRPC; o3co, OPA, Cedar or
  static);
- what an attacker can do — reach a handler without an allow, read a token or
  a decision, make one resource name another — and the steps or a test that
  shows it.

The report is acknowledged in the advisory, and the fix, its release and the
advisory's publication are coordinated with you there.

## Supported versions

Fixes are released as a new version of each affected module, on its newest
minor line. While the major version is `0`, earlier minor lines are not
patched; upgrade to the newest release of the module.

## Scope

This repository enforces authorization decisions; it does not make them. A
vulnerability in how a decision is taken belongs to the backend:
[auth.policy-verifier](https://github.com/o3co/auth.policy-verifier/security),
OPA or Cedar. Report it there. If you are unsure which side it is on, report it
here.
