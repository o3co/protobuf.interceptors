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

package grpc

import (
	"regexp"
	"testing"
	"time"
)

var requestIDShape = regexp.MustCompile(`^[0-9]{14}_[0-9a-f]{16}$`)

func TestRequestIDAt_ShapeAndPrefix(t *testing.T) {
	now := time.Date(2026, 9, 30, 13, 45, 7, 123456789, time.FixedZone("JST", 9*60*60))

	id := requestIDAt(now)

	if !requestIDShape.MatchString(id) {
		t.Fatalf("request ID %q is not YYYYMMDDHHmmss_<16 hex digits>", id)
	}
	// The prefix is the UTC second, so IDs sort by arrival in a log search.
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
