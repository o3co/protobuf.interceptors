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
	"context"
	"strings"

	interceptors "github.com/o3co/protobuf.interceptors"
)

// StaticRule defines an allowed resource/action combination.
// Both Resource and Action support exact match, "*" (wildcard), or "prefix/*" (prefix match).
type StaticRule struct {
	Resource string
	Action   string
}

type staticEndpoint struct {
	rules []StaticRule
}

// NewStaticEndpoint returns a VerifierEndpoint that evaluates authorization
// locally against the given rules, without making any HTTP calls.
func NewStaticEndpoint(rules []StaticRule) VerifierEndpoint {
	r := make([]StaticRule, len(rules))
	copy(r, rules)
	return &staticEndpoint{rules: r}
}

// matchPattern returns true if value matches the given pattern.
// Supported patterns: exact string, "*" (matches any), "prefix/*" (prefix match).
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

// Verify checks that the context carries a bearer token and that at least one
// rule allows the given resource/action combination.
func (e *staticEndpoint) Verify(ctx context.Context, resource, action string) error {
	if _, err := getBearerToken(ctx); err != nil {
		return err
	}
	for _, rule := range e.rules {
		if matchPattern(rule.Resource, resource) && matchPattern(rule.Action, action) {
			return nil
		}
	}
	return &interceptors.DeniedError{Reason: "access denied"}
}
