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
	"errors"

	interceptors "github.com/o3co/protobuf.interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toGRPCError converts framework-neutral errors to gRPC status errors.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	var denied *interceptors.DeniedError
	if errors.As(err, &denied) {
		return status.Error(codes.PermissionDenied, denied.Reason)
	}
	var unauth *interceptors.UnauthenticatedError
	if errors.As(err, &unauth) {
		return status.Error(codes.Unauthenticated, unauth.Reason)
	}
	return status.Errorf(codes.Internal, "%v", err)
}
