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
	"fmt"
	"io"
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
	principalResolver   func(ctx context.Context, token string) string
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
func WithCedarRequestIDHeaderKey(key string) CedarOption {
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

// WithCedarPrincipalResolver sets a custom function to resolve the principal ID from the
// raw bearer token. The default resolver returns the token value as-is.
func WithCedarPrincipalResolver(fn func(ctx context.Context, token string) string) CedarOption {
	if fn == nil {
		panic("principalResolver must not be nil")
	}
	return func(c *cedarBuildConfig) {
		c.principalResolver = fn
	}
}

// WithCedarTransport sets the transport requests to the Cedar agent are sent over:
// an *http.Transport whose TLSClientConfig holds a client certificate or a
// private CA, for one. The endpoint's timeout and redirect policy still apply
// over it. Default is http.DefaultTransport. Panics if rt is nil.
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
	principalResolver   func(ctx context.Context, token string) string
}

// cedarRequest is the JSON body sent to the Cedar agent's is_authorized API.
type cedarRequest struct {
	Principal string         `json:"principal"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Context   map[string]any `json:"context"`
}

// cedarResponse is the JSON body returned by the Cedar agent's is_authorized API.
type cedarResponse struct {
	Decision string `json:"decision"`
}

// formatEntityUID formats a Cedar entity UID as {entityType}::"{id}".
func formatEntityUID(entityType, id string) string {
	return fmt.Sprintf(`%s::"%s"`, entityType, id)
}

// NewCedarEndpoint constructs a VerifierEndpoint that calls the Cedar agent REST API.
// The authorize URL is constructed as: {baseURL}/v1/is_authorized.
// It returns an error unless baseURL names http or https and a host, and
// refuses http to a host other than loopback without WithCedarAllowInsecure.
func NewCedarEndpoint(baseURL string, opts ...CedarOption) (VerifierEndpoint, error) {
	cfg := &cedarBuildConfig{
		timeout:             defaultTimeout,
		maxResponseBodySize: defaultMaxResponseBodySize,
		logger:              newLogger(slog.LevelError),
		requestIDHeaderKey:  "x-request-id",
		principalPrefix:     "User",
		actionPrefix:        "Action",
		resourcePrefix:      "Resource",
		principalResolver:   func(_ context.Context, token string) string { return token },
	}
	for _, opt := range opts {
		opt(cfg)
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

	// Resolve the principal ID from the token.
	principalID := e.principalResolver(ctx, token)

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
		return fmt.Errorf("Cedar agent request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body up to maxResponseBodySize bytes.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, e.maxResponseBodySize))
	if err != nil {
		e.logger.Error("failed to read Cedar agent response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}

	e.logger.Debug("Cedar agent response received", "status", resp.StatusCode, "x-request-id", requestID)

	// Non-2xx responses are treated as internal errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const maxLoggedBodySize = 1024
		logBody := respBody
		if len(logBody) > maxLoggedBodySize {
			logBody = logBody[:maxLoggedBodySize]
		}
		e.logger.Error("error response from Cedar agent", "status", resp.StatusCode, "body", string(logBody), "x-request-id", requestID)
		return fmt.Errorf("Cedar agent returned non-2xx status: %d", resp.StatusCode)
	}

	// Parse the Cedar agent decision.
	var cedarResp cedarResponse
	if err := json.Unmarshal(respBody, &cedarResp); err != nil {
		return fmt.Errorf("failed to parse Cedar agent response: %w", err)
	}

	if cedarResp.Decision == "Allow" {
		return nil
	}

	return &interceptors.DeniedError{Reason: "access denied by policy"}
}
