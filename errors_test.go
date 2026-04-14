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

func TestDeniedError_Error(t *testing.T) {
	err := &interceptors.DeniedError{Reason: "access denied"}
	if err.Error() != "access denied" {
		t.Errorf("Error() = %q, want %q", err.Error(), "access denied")
	}
}

func TestDeniedError_TypeAssertion(t *testing.T) {
	var err error = &interceptors.DeniedError{Reason: "forbidden"}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatal("expected errors.As to match *DeniedError")
	}
	if denied.Reason != "forbidden" {
		t.Errorf("Reason = %q, want %q", denied.Reason, "forbidden")
	}
}

func TestUnauthenticatedError_Error(t *testing.T) {
	err := &interceptors.UnauthenticatedError{Reason: "no token"}
	if err.Error() != "no token" {
		t.Errorf("Error() = %q, want %q", err.Error(), "no token")
	}
}

func TestUnauthenticatedError_TypeAssertion(t *testing.T) {
	var err error = &interceptors.UnauthenticatedError{Reason: "expired"}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatal("expected errors.As to match *UnauthenticatedError")
	}
	if unauth.Reason != "expired" {
		t.Errorf("Reason = %q, want %q", unauth.Reason, "expired")
	}
}
