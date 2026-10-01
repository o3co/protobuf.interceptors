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
//
// The framework interceptors tell the RPC caller only PermissionDenied with
// the fixed message "access denied"; the error itself goes to the
// DecisionObserver.
type DeniedError struct {
	// Reason describes the denial for the service. It never carries the
	// decision, and the framework interceptors never send it to the caller.
	Reason string
	// Decision is what the backend reported behind the denial, nil when it
	// reported nothing or when no backend was asked (see ResourceValueError).
	// It is for the service and never reaches the caller.
	Decision *Decision
}

func (e *DeniedError) Error() string { return e.Reason }

// UnauthenticatedError indicates that the request lacks valid authentication.
// The framework interceptors tell the RPC caller only Unauthenticated with a
// fixed message, never Reason.
type UnauthenticatedError struct {
	Reason string
}

func (e *UnauthenticatedError) Error() string { return e.Reason }

// UnconfirmedRevisionError reports an allow that was not accepted because it
// is not established against confirmed policy revisions (see
// Decision.RevisionConfirmed). Only an endpoint configured to require them
// returns it. It is not a denial — the backend allowed, and the service could
// not establish what the allow rests on — so the framework interceptors map
// it to Internal. Its message says nothing of the decision, nor that a
// revision was required.
type UnconfirmedRevisionError struct {
	// Decision is the allow that was not accepted, nil when the backend
	// reported none at all.
	Decision *Decision
}

func (e *UnconfirmedRevisionError) Error() string {
	return "authorization decision could not be accepted"
}

// ResourceValueError reports a request field value that must not be
// substituted into a resource template.
//
// Resolution refuses a value that is empty or carries a character outside the
// verifier's segment token — notably '.' or ':', which can make the string name
// a different resource type rather than a different instance of the guarded
// one. The refusal is an authorization outcome, not a malformed-input
// report. See README, "Placeholder values", for the accepted set.
type ResourceValueError struct {
	// Placeholder is the placeholder whose value was refused, without the
	// surrounding angle brackets.
	Placeholder string
	// Value is the refused value. It is attacker-controlled request data and
	// is deliberately absent from Error(), so printing the error does not
	// repeat it; it is here for in-process logging that has decided to log it.
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
