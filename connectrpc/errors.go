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
	"errors"

	"connectrpc.com/connect"
	interceptors "github.com/o3co/protobuf.interceptors"
)

// toConnectError converts framework-neutral errors to ConnectRPC errors.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var denied *interceptors.DeniedError
	if errors.As(err, &denied) {
		return connect.NewError(connect.CodePermissionDenied, errors.New(denied.Reason))
	}
	var unauth *interceptors.UnauthenticatedError
	if errors.As(err, &unauth) {
		return connect.NewError(connect.CodeUnauthenticated, errors.New(unauth.Reason))
	}
	return connect.NewError(connect.CodeInternal, err)
}
