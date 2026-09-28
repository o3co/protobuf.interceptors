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

// WithO3coHeaders adds static headers to every outgoing verify request. Later
// calls merge into earlier ones, and win for a header both set.
//
// This exists for auth.policy-verifier's optional http.callerAuth gate, which
// expects a shared credential in a header of its own (x-caller-token by
// default). That credential answers "may you ask for a decision?", which is a
// different question from the subject bearer token in Authorization — so
// turning the gate on requires a header this endpoint would otherwise have no
// way to send.
//
// The headers the endpoint controls itself may not be set here: Content-Type,
// Accept, Authorization and the request-ID header (see
// WithO3coRequestIDHeaderKey). NewO3coEndpoint returns an error rather than
// letting a static header quietly replace the subject token or the content type
// the verifier is answering. Disabling request-ID forwarding releases that
// header, since the endpoint then no longer sets it.
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
// against confirmed policy revisions (see interceptors.Decision.
// RevisionConfirmed): the rule that satisfied every group must report a
// completed evaluation naming a well-formed revision. Such an allow returns
// *interceptors.UnconfirmedRevisionError, which the framework interceptors map
// to Internal. A deny is unaffected.
//
// The verifier reports evaluations only under verify.evaluationInResponse =
// "include", and only for rules backed by a policy evaluator. Against a
// verifier that has not opted in — or whose groups include a rule with no
// policy source — every allow is refused. The verifier has no way to say which
// it is before a decision is asked for, so this cannot be checked at
// construction: the first refused allow whose response carried no evaluation
// at all is logged once, at the error level, naming the setting.
func WithO3coRequireConfirmedRevision() O3coOption {
	return func(c *o3coBuildConfig) {
		c.requireConfirmedRevision = true
	}
}

// endpointControlledHeaders are the headers Verify sets from its own state, and
// which a static header therefore must not overwrite. The request-ID header is
// added to this set at construction, since its name is configurable.
var endpointControlledHeaders = []string{"Content-Type", "Accept", "Authorization"}

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

// validHeaderName reports whether name is a non-empty RFC 7230 field-name.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
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
// Returns an error if baseURL is empty or invalid.
//
// The endpoint it returns is also a DecisionVerifier.
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
		requestIDHeaderKey:  defaultRequestIDHeaderKey,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// After every option is applied: the request-ID header name a static header
	// may collide with is only known once they all have been.
	if err := validateStaticHeaders(cfg.headers, cfg.requestIDHeaderKey); err != nil {
		return nil, err
	}

	return &o3coEndpoint{
		httpClient:               &http.Client{Timeout: cfg.timeout},
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
// The HTTP status decides; the body only adds to it. A 2xx is an allow and a
// 403 a deny whatever the body holds, except that a 2xx whose body is a
// decision other than allow fails closed. A body that is empty, not a
// decision, malformed anywhere or past the size bound reports nothing: the
// decision is nil and the verdict is the status's alone. On a deny the
// decision is also on the *interceptors.DeniedError.
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
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body up to maxResponseBodySize bytes (memory protection).
	// One byte more tells a body at the bound from one past it, which is not
	// read as a decision: a truncated decision would be part of one.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, e.maxResponseBodySize+1))
	if err != nil {
		e.logger.Error("failed to read response body", "error", err, "x-request-id", requestID)
		respBody = nil
	}
	var wire *wireDecision
	if int64(len(respBody)) > e.maxResponseBodySize {
		respBody = respBody[:e.maxResponseBodySize]
		e.logger.Debug("response body exceeds the size bound; not read as a decision", "status", resp.StatusCode, "x-request-id", requestID)
	} else {
		wire = parseDecision(respBody)
	}

	e.logger.Debug("response received", "status", resp.StatusCode, "x-request-id", requestID)

	// --- Evaluate based on status code ----------------------------------------
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return e.acceptAllow(wire, resp.StatusCode, requestID)
	}

	// The body — reason, evaluations, policy ids — stays off the default
	// level; the code alone says which refusal this was.
	var code string
	if wire != nil {
		code = wire.Code
	}
	e.logger.Error("error response from authorization server", "status", resp.StatusCode, "code", code, "x-request-id", requestID)
	const maxLoggedBodySize = 1024
	logBody := respBody
	if len(logBody) > maxLoggedBodySize {
		logBody = logBody[:maxLoggedBodySize]
	}
	e.logger.Debug("error response body", "body", string(logBody), "x-request-id", requestID)

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

// acceptAllow decides what a 2xx answer, carrying wire, amounts to.
func (e *o3coEndpoint) acceptAllow(wire *wireDecision, status int, requestID string) (*interceptors.Decision, error) {
	if wire != nil && wire.Decision != "allow" {
		e.logger.Error("authorization server answered a success status with a decision other than allow", "status", status, "decision", wire.Decision, "x-request-id", requestID)
		return nil, fmt.Errorf("authorization service error: %d with a decision other than allow", status)
	}
	decision := wire.toDecision(requestID)
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
