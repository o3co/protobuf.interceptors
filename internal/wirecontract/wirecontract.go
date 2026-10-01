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

// Package wirecontract reads auth.policy-verifier's wire contract fixtures, so
// that tests hold the o3co endpoint to the verifier's own statement of its
// responses rather than to a copy of it that could drift.
//
// The fixtures live in o3co/auth.policy-verifier under
// tests/integration/src/conformance/fixtures/wireContract. Tests read them from
// the directory named by EnvVar and are skipped when it is unset; CI checks the
// verifier out at a pinned release and sets it.
package wirecontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// EnvVar names the wireContract fixture directory.
const EnvVar = "O3CO_VERIFIER_WIRE_CONTRACT"

// Responses is the part of responseEnvelopes.json these tests read.
type Responses struct {
	Error struct {
		Keys     []string `json:"keys"`
		Decision string   `json:"decision"`
	} `json:"error"`
	Decision struct {
		Required          []string `json:"required"`
		Optional          []string `json:"optional"`
		DenyAlsoCarries   []string `json:"denyAlsoCarries"`
		AllowNeverCarries []string `json:"allowNeverCarries"`
	} `json:"decision"`
	RuleGroup struct {
		Required            []string `json:"required"`
		Optional            []string `json:"optional"`
		OnlyOnAPassingGroup []string `json:"onlyOnAPassingGroup"`
	} `json:"ruleGroup"`
	RuleOutcome struct {
		Required []string `json:"required"`
		Optional []string `json:"optional"`
	} `json:"ruleOutcome"`
	Evaluation struct {
		Statuses   []string `json:"statuses"`
		NotInvoked struct {
			Keys []string `json:"keys"`
		} `json:"notInvoked"`
		Evaluated struct {
			Statuses               []string `json:"statuses"`
			Required               []string `json:"required"`
			OnlyWhenRevisionIsNull []string `json:"onlyWhenRevisionIsNull"`
			OnlyWhenCompleted      []string `json:"onlyWhenCompleted"`
		} `json:"evaluated"`
		DeterminingPolicies struct {
			MaxItems int `json:"maxItems"`
		} `json:"determiningPolicies"`
		Revision struct {
			Pattern   string `json:"pattern"`
			MaxLength int    `json:"maxLength"`
		} `json:"revision"`
	} `json:"evaluation"`
	Status    map[string]int    `json:"status"`
	Codes     map[string]string `json:"codes"`
	RequestID struct {
		Header    string `json:"header"`
		MaxLength int    `json:"maxLength"`
		Pattern   string `json:"pattern"`
	} `json:"requestId"`
}

// Load reads responseEnvelopes.json from the directory EnvVar names. It skips
// the test when EnvVar is unset and fails it when the file cannot be read.
func Load(t testing.TB) *Responses {
	t.Helper()
	dir := os.Getenv(EnvVar)
	if dir == "" {
		t.Skipf("%s is not set: it names auth.policy-verifier's wireContract fixture directory", EnvVar)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "responseEnvelopes.json"))
	if err != nil {
		t.Fatalf("reading the wire contract: %v", err)
	}
	var r Responses
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parsing the wire contract: %v", err)
	}
	return &r
}
