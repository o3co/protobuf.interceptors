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
	"net/url"
	"strings"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// o3coBuildConfig holds temporary configuration used only during NewO3coEndpoint construction.
type o3coBuildConfig struct {
	timeout             time.Duration
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
}

// O3coOption configures the o3co endpoint.
type O3coOption func(*o3coBuildConfig)

// WithO3coTimeout sets the HTTP client timeout. Default is 10s.
func WithO3coTimeout(d time.Duration) O3coOption {
	if d <= 0 {
		panic(fmt.Sprintf("timeout must be positive, got %v", d))
	}
	return func(c *o3coBuildConfig) {
		c.timeout = d
	}
}

// WithO3coMaxResponseBodySize sets the maximum number of bytes to read from the response body.
func WithO3coMaxResponseBodySize(size int64) O3coOption {
	if size <= 0 {
		panic(fmt.Sprintf("maxResponseBodySize must be positive, got %d", size))
	}
	return func(c *o3coBuildConfig) {
		c.maxResponseBodySize = size
	}
}

// WithO3coLogLevel sets the log level. Default is slog.LevelError.
func WithO3coLogLevel(level slog.Level) O3coOption {
	return func(c *o3coBuildConfig) {
		c.logger = newLogger(level)
	}
}

// WithO3coRequestIDHeaderKey sets the HTTP header key for forwarding the request ID.
// Default is "x-request-id". Set to empty string to disable forwarding.
func WithO3coRequestIDHeaderKey(key string) O3coOption {
	return func(c *o3coBuildConfig) {
		c.requestIDHeaderKey = key
	}
}

// o3coEndpoint implements VerifierEndpoint by calling the o3co auth.policy-verifier REST API.
type o3coEndpoint struct {
	httpClient          *http.Client
	verifyURL           string
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
}

// NewO3coEndpoint constructs an o3coEndpoint that calls POST {baseURL}/verify.
// Returns an error if baseURL is empty or invalid.
func NewO3coEndpoint(baseURL string, opts ...O3coOption) (VerifierEndpoint, error) {
	rawBase := strings.TrimSpace(baseURL)
	if rawBase == "" {
		return nil, fmt.Errorf("baseURL must not be empty")
	}

	if !strings.HasPrefix(rawBase, "http://") && !strings.HasPrefix(rawBase, "https://") {
		rawBase = "http://" + rawBase
	}

	base, err := url.Parse(rawBase)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization base url: %w", err)
	}

	base.Path = strings.TrimSuffix(base.Path, "/") + "/verify"

	cfg := &o3coBuildConfig{
		timeout:             defaultTimeout,
		maxResponseBodySize: defaultMaxResponseBodySize,
		logger:              newLogger(slog.LevelError),
		requestIDHeaderKey:  "x-request-id",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &o3coEndpoint{
		httpClient:          &http.Client{Timeout: cfg.timeout},
		verifyURL:           base.String(),
		maxResponseBodySize: cfg.maxResponseBodySize,
		logger:              cfg.logger,
		requestIDHeaderKey:  cfg.requestIDHeaderKey,
	}, nil
}

// Verify executes the authorization check by calling POST /verify on the o3co policy-verifier.
// It reads the bearer token and request ID from ctx.
func (e *o3coEndpoint) Verify(ctx context.Context, resource, action string) error {
	// --- Retrieve bearer token from context -----------------------------------
	token, err := getBearerToken(ctx)
	if err != nil {
		return err
	}

	// --- Build request body ---------------------------------------------------
	reqBody := map[string]any{"resource": resource, "action": action}
	if fields, ok := interceptors.ExtractedFieldsFromContext(ctx); ok && len(fields) > 0 {
		reqBody["context"] = fields
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// --- Create HTTP request --------------------------------------------------
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.verifyURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	var requestID string
	if e.requestIDHeaderKey != "" {
		if id := getRequestID(ctx); id != "" {
			requestID = id
			req.Header.Set(e.requestIDHeaderKey, id)
		}
	}

	// --- Send request ---------------------------------------------------------
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body up to maxResponseBodySize bytes (memory protection).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, e.maxResponseBodySize))
	if err != nil {
		e.logger.Error("failed to read response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}

	e.logger.Debug("response received", "status", resp.StatusCode, "x-request-id", requestID)

	// --- Evaluate based on status code ----------------------------------------
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	const maxLoggedBodySize = 1024
	logBody := respBody
	if len(logBody) > maxLoggedBodySize {
		logBody = logBody[:maxLoggedBodySize]
	}
	e.logger.Error("error response from authorization server", "status", resp.StatusCode, "body", string(logBody), "x-request-id", requestID)

	if resp.StatusCode == http.StatusForbidden {
		return &interceptors.DeniedError{Reason: "access denied"}
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return &interceptors.UnauthenticatedError{Reason: "invalid or expired token"}
	}

	return fmt.Errorf("authorization service error: %d", resp.StatusCode)
}
