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
	"fmt"

	interceptors "github.com/o3co/protobuf.interceptors"
	pb "github.com/o3co/protobuf.interceptors/schema"
	testpb "github.com/o3co/protobuf.interceptors/testproto"
)

// A placeholder is filled from the request field its mapping names. A value
// that would change the structure of the resource string is refused.
func ExampleResolveResource() {
	policy := &pb.Policy{
		Resource: "posts:<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "id"},
		},
	}

	resource, action, err := interceptors.ResolveResource(policy, &testpb.GetResourceByIdRequest{Id: "42"})
	fmt.Println(resource, action, err)

	_, _, err = interceptors.ResolveResource(policy, &testpb.GetResourceByIdRequest{Id: "1.member:2"})
	var refused *interceptors.ResourceValueError
	fmt.Println(errors.As(err, &refused), refused.Placeholder)
	// Output:
	// posts:42 read <nil>
	// true id
}
