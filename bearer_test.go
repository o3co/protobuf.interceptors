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

package interceptors_test

import (
	"errors"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

func TestInboundBearerToken_Absent_IsNoTokenAndNoError(t *testing.T) {
	for _, values := range [][]string{nil, {}} {
		token, err := interceptors.InboundBearerToken(values)
		if err != nil || token != "" {
			t.Errorf("InboundBearerToken(%q) = (%q, %v), want no token and no error", values, token, err)
		}
	}
}

// RFC 9110 §11.1: the authentication scheme is case-insensitive.
func TestInboundBearerToken_SchemeIsCaseInsensitive(t *testing.T) {
	for _, v := range []string{"Bearer tok", "bearer tok", "BEARER tok", "bEaReR tok", "Bearer   tok"} {
		token, err := interceptors.InboundBearerToken([]string{v})
		if err != nil {
			t.Errorf("InboundBearerToken(%q) error = %v", v, err)
			continue
		}
		if token != "tok" {
			t.Errorf("InboundBearerToken(%q) = %q, want %q", v, token, "tok")
		}
	}
}

// A credential that cannot be read as exactly one bearer token is refused,
// never read as an anonymous request.
func TestInboundBearerToken_NotOneBearerCredential_IsUnauthenticated(t *testing.T) {
	for name, values := range map[string][]string{
		"several values":        {"Bearer a", "Bearer b"},
		"several, one empty":    {"Bearer a", ""},
		"empty value":           {""},
		"scheme only":           {"Bearer"},
		"scheme and space":      {"Bearer "},
		"another scheme":        {"Basic dXNlcjpwYXNz"},
		"scheme as prefix":      {"Bearerx tok"},
		"token with space":      {"Bearer a b"},
		"token with tab":        {"Bearer a\tb"},
		"no space after scheme": {"Bearer\ttok"},
	} {
		token, err := interceptors.InboundBearerToken(values)
		var unauth *interceptors.UnauthenticatedError
		if !errors.As(err, &unauth) {
			t.Errorf("%s: InboundBearerToken(%q) error = %v, want *UnauthenticatedError", name, values, err)
		}
		if token != "" {
			t.Errorf("%s: InboundBearerToken(%q) token = %q, want none", name, values, token)
		}
	}
}
