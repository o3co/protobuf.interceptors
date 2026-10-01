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

// opaBuildConfig holds construction-time-only settings for NewOPAEndpoint.
type opaBuildConfig struct {
	timeout             time.Duration
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
	allowInsecure       bool
	transport           http.RoundTripper
}

// OPAOption configures the OPA REST endpoint.
type OPAOption func(*opaBuildConfig)

// WithOPATimeout sets the HTTP client timeout. Panics if d <= 0.
func WithOPATimeout(d time.Duration) OPAOption {
	if d <= 0 {
		panic(fmt.Sprintf("timeout must be positive, got %v", d))
	}
	return func(c *opaBuildConfig) {
		c.timeout = d
	}
}

// WithOPAMaxResponseBodySize sets the maximum number of bytes read from the OPA response body.
// Panics if size <= 0.
func WithOPAMaxResponseBodySize(size int64) OPAOption {
	if size <= 0 {
		panic(fmt.Sprintf("maxResponseBodySize must be positive, got %d", size))
	}
	return func(c *opaBuildConfig) {
		c.maxResponseBodySize = size
	}
}

// WithOPALogLevel sets the log level for the OPA endpoint logger.
func WithOPALogLevel(level slog.Level) OPAOption {
	return func(c *opaBuildConfig) {
		c.logger = newLogger(level)
	}
}

// WithOPARequestIDHeaderKey sets the HTTP header key for forwarding the request ID to OPA.
// Default is "x-request-id". Set to empty string to disable forwarding.
func WithOPARequestIDHeaderKey(key string) OPAOption {
	return func(c *opaBuildConfig) {
		c.requestIDHeaderKey = key
	}
}

// WithOPATransport sets the transport requests to OPA are sent over:
// an *http.Transport whose TLSClientConfig holds a client certificate or a
// private CA, for one. The endpoint's timeout and redirect policy still apply
// over it. Default is http.DefaultTransport. Panics if rt is nil.
func WithOPATransport(rt http.RoundTripper) OPAOption {
	if rt == nil {
		panic("transport must not be nil")
	}
	return func(c *opaBuildConfig) {
		c.transport = rt
	}
}

// WithOPAAllowInsecure permits a plaintext http base URL to a host other than
// loopback. Every request to OPA carries the subject's bearer token, and over
// plaintext anyone on the path can read and replay it, so NewOPAEndpoint
// refuses such a URL without this option.
func WithOPAAllowInsecure() OPAOption {
	return func(c *opaBuildConfig) {
		c.allowInsecure = true
	}
}

// opaEndpoint is a VerifierEndpoint implementation that calls an OPA REST API.
type opaEndpoint struct {
	httpClient          *http.Client
	evaluateURL         string
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
}

// opaRequest is the JSON body sent to OPA's data API.
type opaRequest struct {
	Input opaInput `json:"input"`
}

// opaInput contains the fields evaluated by the OPA policy.
type opaInput struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Token    string `json:"token"`
}

// opaResponse is the JSON body returned by OPA's data API.
// Result is a pointer so we can distinguish false from absent (undefined).
type opaResponse struct {
	Result *bool `json:"result,omitempty"`
}

// NewOPAEndpoint constructs a VerifierEndpoint that calls OPA's REST data API.
// The evaluate URL is constructed as: {baseURL}/v1/data/{policyPath}.
// It returns an error if policyPath is empty or baseURL does not name http or
// https and a host, and refuses http to a host other than loopback without
// WithOPAAllowInsecure.
func NewOPAEndpoint(baseURL, policyPath string, opts ...OPAOption) (VerifierEndpoint, error) {
	rawPath := strings.TrimSpace(policyPath)
	if rawPath == "" {
		return nil, fmt.Errorf("policyPath must not be empty")
	}

	cfg := &opaBuildConfig{
		timeout:             defaultTimeout,
		maxResponseBodySize: defaultMaxResponseBodySize,
		logger:              newLogger(slog.LevelError),
		requestIDHeaderKey:  "x-request-id",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	base, err := parseBaseURL(baseURL, cfg.allowInsecure, "WithOPAAllowInsecure")
	if err != nil {
		return nil, err
	}

	// Normalize: strip trailing slash from base path, strip leading slash from policyPath.
	rawPath = strings.TrimPrefix(rawPath, "/")
	base.Path = strings.TrimSuffix(base.Path, "/") + "/v1/data/" + rawPath

	return &opaEndpoint{
		httpClient:          newHTTPClient(cfg.timeout, cfg.transport),
		evaluateURL:         base.String(),
		maxResponseBodySize: cfg.maxResponseBodySize,
		logger:              cfg.logger,
		requestIDHeaderKey:  cfg.requestIDHeaderKey,
	}, nil
}

// Verify calls the OPA data API and returns nil if the policy result is true,
// *DeniedError if result is false or absent, *UnauthenticatedError if no token,
// and a wrapped error on HTTP or marshaling failures.
func (e *opaEndpoint) Verify(ctx context.Context, resource, action string) error {
	// Retrieve the bearer token from context.
	token, err := getBearerToken(ctx)
	if err != nil {
		return err
	}

	// Build the OPA request body.
	reqBody := opaRequest{
		Input: opaInput{
			Resource: resource,
			Action:   action,
			Token:    token,
		},
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal OPA request body: %w", err)
	}

	// Create the HTTP request, binding the caller's context for cancellation propagation.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.evaluateURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create OPA request: %w", err)
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
		return fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body up to maxResponseBodySize bytes.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, e.maxResponseBodySize))
	if err != nil {
		e.logger.Error("failed to read OPA response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}

	e.logger.Debug("OPA response received", "status", resp.StatusCode, "x-request-id", requestID)

	// Non-2xx responses are treated as internal errors.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.logger.Error("error response from OPA", "status", resp.StatusCode, "x-request-id", requestID)
		e.logger.Debug("error response body", "body", truncatedBody(respBody), "x-request-id", requestID)
		return fmt.Errorf("OPA returned non-2xx status: %d", resp.StatusCode)
	}

	// Parse the OPA decision.
	var opaResp opaResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return fmt.Errorf("failed to parse OPA response: %w", err)
	}

	// result absent (undefined) or false → deny.
	if opaResp.Result == nil || !*opaResp.Result {
		return &interceptors.DeniedError{Reason: "access denied by policy"}
	}

	return nil
}
