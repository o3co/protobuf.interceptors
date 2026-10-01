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
	"context"
	"errors"

	interceptors "github.com/o3co/protobuf.interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toGRPCError converts a framework-neutral error to a gRPC status error. The
// caller is told only the code and a fixed message for it: an endpoint's
// error can name the backend, the URL it called, or why a token was refused.
// The returned error unwraps to err, so an interceptor placed outside these
// can still record it.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	var (
		denied *interceptors.DeniedError
		unauth *interceptors.UnauthenticatedError
	)
	switch {
	case errors.As(err, &denied):
		return &statusError{status.New(codes.PermissionDenied, "access denied"), err}
	case errors.As(err, &unauth):
		return &statusError{status.New(codes.Unauthenticated, "unauthenticated"), err}
	case errors.Is(err, context.Canceled):
		return &statusError{status.New(codes.Canceled, "request canceled"), err}
	case errors.Is(err, context.DeadlineExceeded):
		return &statusError{status.New(codes.DeadlineExceeded, "deadline exceeded"), err}
	default:
		return &statusError{status.New(codes.Internal, "authorization check failed"), err}
	}
}

// statusError is the status the caller receives, wrapping the error behind it.
type statusError struct {
	st    *status.Status
	cause error
}

func (e *statusError) Error() string              { return e.st.Err().Error() }
func (e *statusError) GRPCStatus() *status.Status { return e.st }
func (e *statusError) Unwrap() error              { return e.cause }
