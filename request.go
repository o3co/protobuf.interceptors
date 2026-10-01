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

package interceptors

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

// requestIDPattern and requestIDMaxLength are the x-request-id shape
// auth.policy-verifier accepts: an ID outside it reaches the verifier as none.
// TestRequestIDShape_MatchesTheWireContract holds them to the wire contract.
const (
	requestIDPattern   = `^[A-Za-z0-9\-_.:+/=#]+$`
	requestIDMaxLength = 128
)

var requestIDRE = regexp.MustCompile(requestIDPattern)

// InboundRequestID returns the request ID to carry for a request whose
// x-request-id header or metadata carried values. It keeps the one value sent
// when it is in the shape the verifier accepts, and otherwise — none, several,
// or one outside that shape — returns a generated one, so the ID on the
// context always joins the service's record to the verifier's.
//
// A generated ID is YYYYMMDDHHmmss_<16 hex digits>: the UTC second, so IDs
// sort by arrival to the second, then 8 bytes from crypto/rand, so two
// requests that read the same clock value still get distinct IDs.
func InboundRequestID(values []string) string {
	if len(values) == 1 {
		if id := values[0]; len(id) <= requestIDMaxLength && requestIDRE.MatchString(id) {
			return id
		}
	}
	return requestIDAt(time.Now())
}

// requestIDAt is a generated request ID at the clock value now.
func requestIDAt(now time.Time) string {
	var suffix [8]byte
	// crypto/rand.Read never returns an error: it fills the buffer entirely,
	// or crashes the program if Reader fails.
	_, _ = rand.Read(suffix[:])
	return now.UTC().Format("20060102150405") + "_" + hex.EncodeToString(suffix[:])
}

// InboundBearerToken returns the bearer token of a request whose
// Authorization header or metadata carried values. A request that carried
// none has no token and no error: whether that may proceed is the verifier's
// decision. Otherwise the request must carry exactly one value, of the form
// "Bearer <token>" with the scheme compared case-insensitively (RFC 9110
// §11.1) and a non-empty token without whitespace (RFC 6750 §2.1); anything
// else is an *UnauthenticatedError rather than an anonymous request.
func InboundBearerToken(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	if len(values) == 1 {
		scheme, token, ok := strings.Cut(values[0], " ")
		token = strings.TrimLeft(token, " ")
		if ok && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t") {
			return token, nil
		}
	}
	return "", &UnauthenticatedError{Reason: "authorization is not exactly one bearer credential"}
}
