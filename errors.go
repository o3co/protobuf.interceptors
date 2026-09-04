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

// DeniedError indicates that the authorization check denied the request.
type DeniedError struct {
	Reason string
}

func (e *DeniedError) Error() string { return e.Reason }

// UnauthenticatedError indicates that the request lacks valid authentication.
type UnauthenticatedError struct {
	Reason string
}

func (e *UnauthenticatedError) Error() string { return e.Reason }

// ResourceValueError reports a request field value that must not be
// substituted into a resource template.
//
// The resolved resource string is parsed by the authorization backend, so a
// value carrying a character that is structural in that grammar does not
// identify a different instance of the guarded resource type — it names a
// different resource type. Resolution refuses such a value instead of building
// the string, which is why this is an authorization outcome and not a
// malformed-input report. See resourceValueRune in resolve.go for the accepted
// character set and the grammar it is anchored to.
type ResourceValueError struct {
	// Placeholder is the placeholder whose value was refused, without the
	// surrounding angle brackets.
	Placeholder string
	// Value is the refused value. It is attacker-controlled request data and
	// is deliberately absent from Error(), so it is not echoed back over the
	// wire; it is here for in-process logging that has decided to log it.
	Value string
	// Reason states what disqualified the value.
	Reason string
}

func (e *ResourceValueError) Error() string {
	return "resource placeholder <" + e.Placeholder + ">: " + e.Reason
}

// Unwrap reports the refusal as a denial, so that the framework interceptors'
// error mapping (toGRPCError / toConnectError) turns it into PermissionDenied.
// A refused substitution is a fail-closed authorization decision: the request
// asked for a resource that cannot be named, and no backend was consulted.
func (e *ResourceValueError) Unwrap() error { return &DeniedError{Reason: e.Error()} }
