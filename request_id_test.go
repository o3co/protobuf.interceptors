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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/o3co/protobuf.interceptors/internal/wirecontract"
)

var generatedRequestIDShape = regexp.MustCompile(`^[0-9]{14}_[0-9a-f]{16}$`)

func TestInboundRequestID_Absent_IsGenerated(t *testing.T) {
	for _, values := range [][]string{nil, {}, {""}} {
		if id := InboundRequestID(values); !generatedRequestIDShape.MatchString(id) {
			t.Errorf("InboundRequestID(%q) = %q, want a generated ID", values, id)
		}
	}
}

func TestInboundRequestID_InTheVerifiersShape_IsKept(t *testing.T) {
	for _, id := range []string{
		"req-1",
		"0f8fad5b-d9cb-469f-a165-70867728950e",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"YWJj+/=#:._-",
		strings.Repeat("a", 128),
	} {
		if got := InboundRequestID([]string{id}); got != id {
			t.Errorf("InboundRequestID(%q) = %q, want it kept", id, got)
		}
	}
}

// An ID outside the verifier's shape reaches the verifier as none and joins
// nothing, so it is replaced rather than carried.
func TestInboundRequestID_OutsideTheVerifiersShape_IsReplaced(t *testing.T) {
	for _, id := range []string{
		strings.Repeat("a", 129),
		"has space",
		"line\nbreak",
		"café",
		"<script>",
		"semi;colon",
	} {
		got := InboundRequestID([]string{id})
		if got == id {
			t.Errorf("InboundRequestID(%q) kept an ID outside the verifier's shape", id)
		}
		if !generatedRequestIDShape.MatchString(got) {
			t.Errorf("InboundRequestID(%q) = %q, want a generated ID", id, got)
		}
	}
}

// Several values do not say which one is the request's ID.
func TestInboundRequestID_SeveralValues_IsReplaced(t *testing.T) {
	got := InboundRequestID([]string{"req-1", "req-2"})
	if !generatedRequestIDShape.MatchString(got) {
		t.Errorf("InboundRequestID with two values = %q, want a generated ID", got)
	}
}

func TestInboundRequestID_GeneratedIDsAreInTheVerifiersShape(t *testing.T) {
	id := InboundRequestID(nil)
	if InboundRequestID([]string{id}) != id {
		t.Errorf("generated ID %q is outside the shape the verifier accepts", id)
	}
}

func TestRequestIDAt_ShapeAndPrefix(t *testing.T) {
	now := time.Date(2026, 9, 30, 13, 45, 7, 123456789, time.FixedZone("JST", 9*60*60))

	id := requestIDAt(now)

	if !generatedRequestIDShape.MatchString(id) {
		t.Fatalf("request ID %q is not YYYYMMDDHHmmss_<16 hex digits>", id)
	}
	// The prefix is the UTC second, so IDs sort by arrival to the second.
	if got, want := id[:14], "20260930044507"; got != want {
		t.Fatalf("prefix = %q, want the UTC second %q", got, want)
	}
}

// Two requests that read the same clock value must not share an ID: the
// ID joins a service's record to the verifier's decision line.
func TestRequestIDAt_SameClockValueGivesDistinctIDs(t *testing.T) {
	now := time.Date(2026, 9, 30, 4, 45, 7, 0, time.UTC)
	seen := make(map[string]bool)

	for range 1000 {
		id := requestIDAt(now)
		if seen[id] {
			t.Fatalf("request ID %q issued twice for one clock value", id)
		}
		seen[id] = true
	}
}

func TestRequestIDShape_MatchesTheWireContract(t *testing.T) {
	c := wirecontract.Load(t)
	if c.RequestID.Pattern != requestIDPattern {
		t.Errorf("requestIDPattern = %q, the wire contract says %q", requestIDPattern, c.RequestID.Pattern)
	}
	if c.RequestID.MaxLength != requestIDMaxLength {
		t.Errorf("requestIDMaxLength = %d, the wire contract says %d", requestIDMaxLength, c.RequestID.MaxLength)
	}
}
