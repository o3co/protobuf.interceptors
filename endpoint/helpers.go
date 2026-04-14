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

package endpoint

import (
	"context"
	"time"

	interceptors "github.com/o3co/protobuf.interceptors"
)

const defaultMaxResponseBodySize int64 = 1024 * 1024 // 1MB
const defaultTimeout = 10 * time.Second

// getBearerToken retrieves the bearer token from the context.
func getBearerToken(ctx context.Context) (string, error) {
	token, ok := interceptors.BearerTokenFromContext(ctx)
	if !ok || token == "" {
		return "", &interceptors.UnauthenticatedError{Reason: "no bearer token in context"}
	}
	return token, nil
}

// getRequestID retrieves the request ID from the context.
func getRequestID(ctx context.Context) string {
	return interceptors.RequestIDFromContext(ctx)
}
