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

package methodset_test

import (
	"testing"

	"github.com/o3co/protobuf.interceptors/internal/methodset"
)

func TestParse_Contains(t *testing.T) {
	set, err := methodset.Parse([]string{
		"/pkg.v1.Svc/Get",
		"/grpc.health.v1.Health/",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, tc := range []struct {
		method string
		want   bool
	}{
		{"/pkg.v1.Svc/Get", true},
		{"/pkg.v1.Svc/List", false},
		{"/pkg.v1.Svc/Ge", false},
		{"/pkg.v1.Svc/GetX", false},
		{"/pkg.v1.Svc2/Get", false},
		{"/grpc.health.v1.Health/Check", true},
		{"/grpc.health.v1.Health/Watch", true},
		{"/grpc.health.v1.HealthX/Check", false},
		{"/grpc.health.v1/Health/Check", false},
		{"/other.Svc/Get", false},
		{"", false},
		{"/", false},
		{"/grpc.health.v1.Health/", false},
	} {
		if got := set.Contains(tc.method); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

func TestParse_Empty(t *testing.T) {
	set, err := methodset.Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Contains("/pkg.Svc/Get") {
		t.Error("an empty set contains a method")
	}
}

func TestParse_Malformed(t *testing.T) {
	for _, entry := range []string{
		"",
		"/",
		"//",
		"pkg.Svc/Get",
		"/pkg.Svc",
		"/pkg.Svc/Get/",
		"/pkg.Svc/Get/More",
		"//Get",
		"/pkg..Svc/Get",
		"/.pkg.Svc/Get",
		"/pkg.Svc./Get",
		"/pkg.Svc/Get.More",
		"/pkg Svc/Get",
		"/pkg.Svc/ Get",
		"/pkg.Svc/Get ",
		"/pkg.Svc/*",
		"/pkg.*/",
		"/1pkg.Svc/Get",
		"/pkg.Svc/1Get",
	} {
		if _, err := methodset.Parse([]string{"/ok.Svc/", entry}); err == nil {
			t.Errorf("Parse(%q) accepted a malformed entry", entry)
		}
	}
}

func TestSet_Union(t *testing.T) {
	a, _ := methodset.Parse([]string{"/a.Svc/"})
	b, _ := methodset.Parse([]string{"/b.Svc/Get"})
	u := a.Union(b)
	if !u.Contains("/a.Svc/Any") || !u.Contains("/b.Svc/Get") {
		t.Error("the union lost an entry")
	}
	if a.Contains("/b.Svc/Get") || b.Contains("/a.Svc/Any") {
		t.Error("Union changed an operand")
	}
}
