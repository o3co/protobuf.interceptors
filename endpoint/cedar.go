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

package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// cedarBuildConfig holds construction-time-only settings for NewCedarEndpoint.
type cedarBuildConfig struct {
	timeout             time.Duration
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
	principalPrefix     string
	actionPrefix        string
	resourcePrefix      string
	principalResolver   func(ctx context.Context, token string) (string, error)
	allowInsecure       bool
	transport           http.RoundTripper
}

// CedarOption configures the Cedar agent REST endpoint.
type CedarOption func(*cedarBuildConfig)

// WithCedarTimeout sets the HTTP client timeout. Panics if d <= 0.
func WithCedarTimeout(d time.Duration) CedarOption {
	if d <= 0 {
		panic(fmt.Sprintf("timeout must be positive, got %v", d))
	}
	return func(c *cedarBuildConfig) {
		c.timeout = d
	}
}

// WithCedarMaxResponseBodySize sets the maximum number of bytes read from the Cedar agent
// response body. Panics if size <= 0.
func WithCedarMaxResponseBodySize(size int64) CedarOption {
	if size <= 0 {
		panic(fmt.Sprintf("maxResponseBodySize must be positive, got %d", size))
	}
	return func(c *cedarBuildConfig) {
		c.maxResponseBodySize = size
	}
}

// WithCedarLogLevel sets the log level for the Cedar endpoint logger.
func WithCedarLogLevel(level slog.Level) CedarOption {
	return func(c *cedarBuildConfig) {
		c.logger = newLogger(level)
	}
}

// WithCedarRequestIDHeaderKey sets the HTTP header key for forwarding the request ID
// to the Cedar agent. Default is "x-request-id". Set to empty string to disable forwarding.
// Panics if key is not an RFC 7230 token, or is Authorization, Content-Type
// or Accept.
func WithCedarRequestIDHeaderKey(key string) CedarOption {
	mustBeRequestIDHeaderKey(key)
	return func(c *cedarBuildConfig) {
		c.requestIDHeaderKey = key
	}
}

// WithCedarPrincipalPrefix sets the Cedar entity type prefix for the principal.
// Default is "User".
func WithCedarPrincipalPrefix(prefix string) CedarOption {
	return func(c *cedarBuildConfig) {
		c.principalPrefix = prefix
	}
}

// WithCedarActionPrefix sets the Cedar entity type prefix for the action.
// Default is "Action".
func WithCedarActionPrefix(prefix string) CedarOption {
	return func(c *cedarBuildConfig) {
		c.actionPrefix = prefix
	}
}

// WithCedarResourcePrefix sets the Cedar entity type prefix for the resource.
// Default is "Resource".
func WithCedarResourcePrefix(prefix string) CedarOption {
	return func(c *cedarBuildConfig) {
		c.resourcePrefix = prefix
	}
}

// WithCedarPrincipalResolver sets the function that authenticates the bearer
// token and returns the id of the principal it stands for. NewCedarEndpoint
// requires it: the Cedar agent decides for whatever principal it is given and
// authenticates nothing, so the resolver is where the token is checked, and
// must verify it — a JWT's signature, expiry, issuer and audience — rather
// than only read it. An error or an empty id refuses the request as
// *interceptors.UnauthenticatedError before the agent is asked; the error
// does not reach the RPC caller. Panics if fn is nil.
func WithCedarPrincipalResolver(fn func(ctx context.Context, token string) (string, error)) CedarOption {
	if fn == nil {
		panic("principalResolver must not be nil")
	}
	return func(c *cedarBuildConfig) {
		c.principalResolver = fn
	}
}

// WithCedarTransport sets the transport requests to the Cedar agent are sent over:
// an *http.Transport whose TLSClientConfig holds a client certificate or a
// private CA, for one. The endpoint's timeout and its refusal to follow
// redirects hold over a transport that honours the request's context and does
// not follow redirects itself, as *http.Transport does. Default is
// http.DefaultTransport. Panics if rt is nil.
func WithCedarTransport(rt http.RoundTripper) CedarOption {
	if rt == nil {
		panic("transport must not be nil")
	}
	return func(c *cedarBuildConfig) {
		c.transport = rt
	}
}

// WithCedarAllowInsecure permits a plaintext http base URL to a host other
// than loopback. Over plaintext anyone on the path can read and alter what is
// asked and what is answered, so NewCedarEndpoint refuses such a URL without
// this option.
func WithCedarAllowInsecure() CedarOption {
	return func(c *cedarBuildConfig) {
		c.allowInsecure = true
	}
}

// cedarEndpoint is a VerifierEndpoint implementation that calls a Cedar agent REST API.
type cedarEndpoint struct {
	httpClient          *http.Client
	authorizeURL        string
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
	principalPrefix     string
	actionPrefix        string
	resourcePrefix      string
	principalResolver   func(ctx context.Context, token string) (string, error)
}

// cedarRequest is the JSON body sent to the Cedar agent's is_authorized API.
type cedarRequest struct {
	Principal string         `json:"principal"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Context   map[string]any `json:"context"`
}

// formatEntityUID formats a Cedar entity UID, {entityType}::"{id}", with id
// escaped as a Cedar string literal. Unescaped, a quote or backslash in id
// would end the literal or escape what follows it, and the UID would name
// another entity or none. Control characters are escaped as \u{...} too.
func formatEntityUID(entityType, id string) string {
	var b strings.Builder
	b.WriteString(entityType)
	b.WriteString(`::"`)
	for _, r := range id {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// NewCedarEndpoint constructs a VerifierEndpoint that calls the Cedar agent REST API.
// The authorize URL is constructed as: {baseURL}/v1/is_authorized.
// It returns an error without WithCedarPrincipalResolver, or unless baseURL
// names http or https and a host, and refuses http to a host other than
// loopback without WithCedarAllowInsecure.
//
// The endpoint does no authentication of its own: the principal it asks
// about is the one the resolver returns.
func NewCedarEndpoint(baseURL string, opts ...CedarOption) (VerifierEndpoint, error) {
	cfg := &cedarBuildConfig{
		timeout:             defaultTimeout,
		maxResponseBodySize: defaultMaxResponseBodySize,
		logger:              newLogger(slog.LevelError),
		requestIDHeaderKey:  "x-request-id",
		principalPrefix:     "User",
		actionPrefix:        "Action",
		resourcePrefix:      "Resource",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.principalResolver == nil {
		return nil, errors.New("a principal resolver is required: WithCedarPrincipalResolver authenticates the bearer token and names the principal")
	}

	base, err := parseBaseURL(baseURL, cfg.allowInsecure, "WithCedarAllowInsecure")
	if err != nil {
		return nil, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/v1/is_authorized"

	return &cedarEndpoint{
		httpClient:          newHTTPClient(cfg.timeout, cfg.transport),
		authorizeURL:        base.String(),
		maxResponseBodySize: cfg.maxResponseBodySize,
		logger:              cfg.logger,
		requestIDHeaderKey:  cfg.requestIDHeaderKey,
		principalPrefix:     cfg.principalPrefix,
		actionPrefix:        cfg.actionPrefix,
		resourcePrefix:      cfg.resourcePrefix,
		principalResolver:   cfg.principalResolver,
	}, nil
}

// Verify calls the Cedar agent is_authorized API and returns nil if the decision is "Allow",
// *DeniedError for any other decision, *UnauthenticatedError if no token is present,
// and a wrapped error on HTTP or marshaling failures.
func (e *cedarEndpoint) Verify(ctx context.Context, resource, action string) error {
	// Retrieve the bearer token from context.
	token, err := getBearerToken(ctx)
	if err != nil {
		return err
	}

	principalID, err := e.principalResolver(ctx, token)
	if err != nil || principalID == "" {
		e.logger.Debug("principal resolver refused the bearer token", "error", err, "x-request-id", getRequestID(ctx))
		return &interceptors.UnauthenticatedError{Reason: "invalid or expired token"}
	}

	// Build the Cedar agent request body using entity UID format.
	reqBody := cedarRequest{
		Principal: formatEntityUID(e.principalPrefix, principalID),
		Action:    formatEntityUID(e.actionPrefix, action),
		Resource:  formatEntityUID(e.resourcePrefix, resource),
		Context:   map[string]any{},
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal Cedar agent request body: %w", err)
	}

	// Create the HTTP request, binding the caller's context for cancellation propagation.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.authorizeURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create Cedar agent request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var requestID string
	if e.requestIDHeaderKey != "" {
		if id := getRequestID(ctx); id != "" {
			requestID = id
			req.Header.Set(e.requestIDHeaderKey, id)
		}
	}

	// Send the request.
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return requestError(ctx, "request to the Cedar agent failed", err)
	}
	defer resp.Body.Close()

	respBody, oversized, err := readBounded(resp.Body, e.maxResponseBodySize)
	if err != nil {
		if ctx.Err() != nil {
			return requestError(ctx, "reading the Cedar agent response failed", err)
		}
		e.logger.Error("failed to read Cedar agent response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}

	e.logger.Debug("Cedar agent response received", "status", resp.StatusCode, "x-request-id", requestID)

	// Non-2xx responses are treated as internal errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.logger.Error("error response from Cedar agent", "status", resp.StatusCode, "x-request-id", requestID)
		e.logger.Debug("error response body", "body", truncatedBody(respBody), "x-request-id", requestID)
		return fmt.Errorf("the Cedar agent returned non-2xx status: %d", resp.StatusCode)
	}

	if oversized {
		e.logger.Error("Cedar agent response body exceeds the size bound", "status", resp.StatusCode, "x-request-id", requestID)
		return errors.New("the Cedar agent response body exceeds the size bound")
	}

	// Only the exact key decision, holding "Allow", allows: the agent's keys
	// are case-sensitive, and a key in another case is not the decision.
	obj, ok := decodeObject(respBody)
	if !ok {
		return errors.New("failed to parse Cedar agent response: not a JSON object")
	}
	if obj["decision"] == "Allow" {
		return nil
	}
	return &interceptors.DeniedError{Reason: "access denied by policy"}
}
