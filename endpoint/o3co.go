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
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
)

const defaultRequestIDHeaderKey = "x-request-id"

// o3coBuildConfig holds temporary configuration used only during NewO3coEndpoint construction.
type o3coBuildConfig struct {
	timeout                  time.Duration
	maxResponseBodySize      int64
	logger                   *slog.Logger
	requestIDHeaderKey       string
	headers                  http.Header
	requireConfirmedRevision bool
	allowInsecure            bool
	transport                http.RoundTripper
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
// Panics if key is not an RFC 7230 token, or is Authorization, Content-Type
// or Accept.
func WithO3coRequestIDHeaderKey(key string) O3coOption {
	mustBeRequestIDHeaderKey(key)
	return func(c *o3coBuildConfig) {
		c.requestIDHeaderKey = key
	}
}

// WithO3coHeaders adds static headers to every outgoing verify request. Later
// calls merge into earlier ones, and win for a header both set.
//
// Use it to send the shared credential that auth.policy-verifier's optional
// http.callerAuth gate expects (x-caller-token by default). That credential
// answers "may this service ask for a decision?", not who the subject is,
// which Authorization carries.
//
// The headers the endpoint controls itself may not be set here: Content-Type,
// Accept, Authorization and the request-ID header (see
// WithO3coRequestIDHeaderKey). NewO3coEndpoint returns an error rather than
// letting a static header replace the subject token or the content type.
// Disabling request-ID forwarding releases that header, which the endpoint then
// does not set.
func WithO3coHeaders(headers map[string]string) O3coOption {
	return func(c *o3coBuildConfig) {
		if c.headers == nil {
			c.headers = make(http.Header, len(headers))
		}
		for k, v := range headers {
			c.headers.Set(k, v)
		}
	}
}

// WithO3coRequireConfirmedRevision refuses an allow that is not established
// against confirmed policy revisions (see
// [interceptors.Decision.RevisionConfirmed]) with
// *interceptors.UnconfirmedRevisionError, which the framework interceptors map
// to Internal. A deny is unaffected.
//
// The verifier reports evaluations only under verify.evaluationInResponse =
// "include", and only for rules backed by a policy evaluator. Against a
// verifier that has not opted in, every allow is refused, and so is an allow
// in which a rule with no policy source satisfied a granting group, or whose
// every group restricts (see [interceptors.RuleGroup.Restricts]). That
// cannot be checked at construction, so the first refused allow whose
// response carried no evaluation at all is logged once, at the error level,
// naming the setting.
func WithO3coRequireConfirmedRevision() O3coOption {
	return func(c *o3coBuildConfig) {
		c.requireConfirmedRevision = true
	}
}

// WithO3coTransport sets the transport requests to the verifier are sent over:
// an *http.Transport whose TLSClientConfig holds a client certificate or a
// private CA, for one. The endpoint's timeout and redirect policy still apply
// over it. Default is http.DefaultTransport. Panics if rt is nil.
func WithO3coTransport(rt http.RoundTripper) O3coOption {
	if rt == nil {
		panic("transport must not be nil")
	}
	return func(c *o3coBuildConfig) {
		c.transport = rt
	}
}

// WithO3coAllowInsecure permits a plaintext http base URL to a host other
// than loopback. Every verify request carries the subject's bearer token, and
// over plaintext anyone on the path can read and replay it, so
// NewO3coEndpoint refuses such a URL without this option.
func WithO3coAllowInsecure() O3coOption {
	return func(c *o3coBuildConfig) {
		c.allowInsecure = true
	}
}

// validateStaticHeaders refuses a static header that would override one of the
// endpoint's own, or that is not a well-formed header at all. Rejecting CR, LF
// and NUL in a value here means a bad value fails at construction rather than
// at the first Verify.
func validateStaticHeaders(headers http.Header, requestIDHeaderKey string) error {
	if len(headers) == 0 {
		return nil
	}

	controlled := make(map[string]struct{}, len(endpointControlledHeaders)+1)
	for _, name := range endpointControlledHeaders {
		controlled[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	if requestIDHeaderKey != "" {
		controlled[http.CanonicalHeaderKey(requestIDHeaderKey)] = struct{}{}
	}

	for name, values := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid header name %q", name)
		}
		if _, isControlled := controlled[http.CanonicalHeaderKey(name)]; isControlled {
			return fmt.Errorf("header %q is set by the endpoint and must not be overridden", name)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("invalid value for header %q: control characters are not allowed", name)
			}
		}
	}
	return nil
}

// o3coEndpoint implements DecisionVerifier by calling the o3co auth.policy-verifier REST API.
type o3coEndpoint struct {
	httpClient          *http.Client
	verifyURL           string
	maxResponseBodySize int64
	logger              *slog.Logger
	requestIDHeaderKey  string
	// headers are set on every request before the endpoint's own, and are
	// never mutated after construction.
	headers                  http.Header
	requireConfirmedRevision bool
	// noEvaluationHint logs, once, that strict mode is refusing allows that
	// carry no evaluation at all.
	noEvaluationHint sync.Once
}

// NewO3coEndpoint constructs an o3coEndpoint that calls POST {baseURL}/verify.
// It returns an error unless baseURL names http or https and a host, and
// refuses http to a host other than loopback without WithO3coAllowInsecure.
//
// The endpoint it returns is also a DecisionVerifier.
func NewO3coEndpoint(baseURL string, opts ...O3coOption) (VerifierEndpoint, error) {
	cfg := &o3coBuildConfig{
		timeout:             defaultTimeout,
		maxResponseBodySize: defaultMaxResponseBodySize,
		logger:              newLogger(slog.LevelError),
		requestIDHeaderKey:  defaultRequestIDHeaderKey,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	base, err := parseBaseURL(baseURL, cfg.allowInsecure, "WithO3coAllowInsecure")
	if err != nil {
		return nil, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/verify"

	// After every option is applied: the request-ID header name a static header
	// may collide with is only known once they all have been.
	if err := validateStaticHeaders(cfg.headers, cfg.requestIDHeaderKey); err != nil {
		return nil, err
	}

	return &o3coEndpoint{
		httpClient:               newHTTPClient(cfg.timeout, cfg.transport),
		verifyURL:                base.String(),
		maxResponseBodySize:      cfg.maxResponseBodySize,
		logger:                   cfg.logger,
		requestIDHeaderKey:       cfg.requestIDHeaderKey,
		headers:                  cfg.headers,
		requireConfirmedRevision: cfg.requireConfirmedRevision,
	}, nil
}

// Verify executes the authorization check by calling POST /verify on the o3co policy-verifier.
// It reads the bearer token and request ID from ctx.
func (e *o3coEndpoint) Verify(ctx context.Context, resource, action string) error {
	_, err := e.VerifyDecision(ctx, resource, action)
	return err
}

// VerifyDecision is Verify, and also returns the decision the verifier sent.
//
// An allow takes both the status and the body: a 200 whose body is a whole
// decision envelope, as the wire contract defines it, with decision "allow".
// Any other 2xx, and a 200 whose body is empty, not a whole envelope, past the
// size bound, cut off while reading or a whole deny, is an error, never an
// allow. A 403 is a deny whatever its body holds. A body that is not a whole
// envelope reports nothing, so the decision is then nil; a whole one is
// returned with any verdict. On a deny the decision is also on the
// *interceptors.DeniedError.
func (e *o3coEndpoint) VerifyDecision(ctx context.Context, resource, action string) (*interceptors.Decision, error) {
	// --- Retrieve bearer token from context -----------------------------------
	token, err := getBearerToken(ctx)
	if err != nil {
		return nil, err
	}

	// --- Build request body ---------------------------------------------------
	reqBody := map[string]any{"resource": resource, "action": action}
	if fields, ok := interceptors.ExtractedFieldsFromContext(ctx); ok && len(fields) > 0 {
		reqBody["context"] = fields
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// --- Create HTTP request --------------------------------------------------
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.verifyURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Static headers first, so the endpoint's own always win even though the
	// constructor already refused a static header that collides with one.
	for name, values := range e.headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
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
		return nil, requestError(ctx, "request failed", err)
	}
	defer resp.Body.Close()

	respBody, oversized, err := readBounded(resp.Body, e.maxResponseBodySize)
	if err != nil {
		if ctx.Err() != nil {
			return nil, requestError(ctx, "reading the response failed", err)
		}
		e.logger.Error("failed to read response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	var wire *wireDecision
	if oversized {
		e.logger.Debug("response body exceeds the size bound; not read as a decision", "status", resp.StatusCode, "x-request-id", requestID)
	} else if obj, ok := decodeObject(respBody); ok {
		kind := errorEnvelope
		if success || resp.StatusCode == http.StatusForbidden {
			kind = decisionEnvelope
		}
		wire = parseEnvelope(obj, kind)
	}

	e.logger.Debug("response received", "status", resp.StatusCode, "x-request-id", requestID)

	// --- Evaluate based on status code ----------------------------------------
	if success {
		return e.acceptAllow(wire, resp.StatusCode, requestID)
	}

	// The body — reason, evaluations, policy ids — stays off the default
	// level; the code alone says which refusal this was.
	var code string
	if wire != nil {
		code = wire.Code
	}
	e.logger.Error("error response from authorization server", "status", resp.StatusCode, "code", code, "x-request-id", requestID)
	e.logger.Debug("error response body", "body", truncatedBody(respBody), "x-request-id", requestID)

	if resp.StatusCode == http.StatusForbidden {
		decision := wire.toDecision(requestID)
		return decision, &interceptors.DeniedError{Reason: "access denied", Decision: decision}
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// The verifier answers 401 for the subject's token and for this
		// service's caller credential alike; only the code tells them apart.
		if code == codeCallerUnauthenticated {
			return nil, ErrCallerUnauthenticated
		}
		return nil, &interceptors.UnauthenticatedError{Reason: "invalid or expired token"}
	}

	return nil, fmt.Errorf("authorization service error: %d", resp.StatusCode)
}

// acceptAllow decides what a 2xx answer amounts to. wire is the envelope read
// from its body, nil when the body is not a whole one.
func (e *o3coEndpoint) acceptAllow(wire *wireDecision, status int, requestID string) (*interceptors.Decision, error) {
	decision := wire.toDecision(requestID)
	// The body is not logged at the default level: it may carry the
	// decision's reasons, evaluations and policy ids.
	if status != http.StatusOK || wire == nil || wire.Decision != "allow" {
		e.logger.Error("authorization server answered a success status without a whole allow", "status", status, "x-request-id", requestID)
		return decision, fmt.Errorf("authorization service error: %d without a whole allow", status)
	}
	if e.requireConfirmedRevision && !decision.RevisionConfirmed() {
		if !carriesEvaluation(decision) {
			e.noEvaluationHint.Do(func() {
				e.logger.Error("refusing allows for want of a confirmed policy revision, and the verifier sent no evaluation at all: " +
					"it reports them only under verify.evaluationInResponse = \"include\", and until it does every allow is refused")
			})
		}
		return decision, &interceptors.UnconfirmedRevisionError{Decision: decision}
	}
	return decision, nil
}

// carriesEvaluation reports whether any rule outcome of d carries an evaluation.
func carriesEvaluation(d *interceptors.Decision) bool {
	if d == nil {
		return false
	}
	for _, g := range d.Groups {
		for _, o := range g.Evaluated {
			if o.Evaluation != nil {
				return true
			}
		}
		if g.SatisfiedBy != nil && g.SatisfiedBy.Evaluation != nil {
			return true
		}
	}
	return false
}
