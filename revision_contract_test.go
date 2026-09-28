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
	"slices"
	"testing"

	"github.com/o3co/protobuf.interceptors/internal/wirecontract"
)

func TestRevisionGrammar_MatchesTheWireContract(t *testing.T) {
	c := wirecontract.Load(t)
	if c.Evaluation.Revision.Pattern != revisionPattern {
		t.Errorf("revisionPattern = %q, the wire contract says %q", revisionPattern, c.Evaluation.Revision.Pattern)
	}
	if c.Evaluation.Revision.MaxLength != revisionMaxLength {
		t.Errorf("revisionMaxLength = %d, the wire contract says %d", revisionMaxLength, c.Evaluation.Revision.MaxLength)
	}
}

func TestEvaluationStatuses_MatchTheWireContract(t *testing.T) {
	c := wirecontract.Load(t)
	ours := []string{string(EvaluationCompleted), string(EvaluationFailed), string(EvaluationNotInvoked)}
	theirs := slices.Clone(c.Evaluation.Statuses)
	slices.Sort(ours)
	slices.Sort(theirs)
	if !slices.Equal(ours, theirs) {
		t.Errorf("evaluation statuses = %v, the wire contract says %v", ours, theirs)
	}
}
