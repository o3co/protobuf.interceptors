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

package connectrpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
)

// toConnectError converts a framework-neutral error to a ConnectRPC error. The
// caller is told only the code and a fixed message for it: an endpoint's
// error can name the backend, the URL it called, or why a token was refused.
// The returned error unwraps to err, so an interceptor placed outside these
// can still record it.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var (
		denied *interceptors.DeniedError
		unauth *interceptors.UnauthenticatedError
	)
	switch {
	case errors.As(err, &denied):
		return connect.NewError(connect.CodePermissionDenied, &fixedMessage{"access denied", err})
	case errors.As(err, &unauth):
		return connect.NewError(connect.CodeUnauthenticated, &fixedMessage{"unauthenticated", err})
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, &fixedMessage{"request canceled", err})
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, &fixedMessage{"deadline exceeded", err})
	default:
		return connect.NewError(connect.CodeInternal, &fixedMessage{"authorization check failed", err})
	}
}

// fixedMessage is what the caller is told, wrapping the error behind it.
type fixedMessage struct {
	message string
	cause   error
}

func (e *fixedMessage) Error() string { return e.message }
func (e *fixedMessage) Unwrap() error { return e.cause }
