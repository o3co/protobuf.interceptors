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
	"fmt"
	"strings"
	"sync"

	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

type rpcMethod struct {
	Service string
	Method  string
}

func parseFullMethodName(fullMethodName string) (rpcMethod, error) {
	if len(fullMethodName) == 0 || fullMethodName[0] != '/' {
		return rpcMethod{}, fmt.Errorf("invalid full method format: %s", fullMethodName)
	}
	method := fullMethodName[1:]
	lastSlash := strings.LastIndex(method, "/")
	if lastSlash == -1 {
		return rpcMethod{}, fmt.Errorf("invalid full method format: %s", fullMethodName)
	}
	return rpcMethod{Service: method[:lastSlash], Method: method[lastSlash+1:]}, nil
}

// getMethodPolicy returns the policy of the method fullMethodName names, nil
// when its descriptor carries no policy option. A method whose descriptor is
// not registered is an error, not "no policy": its policy cannot be known.
//
// Only found methods are cached, so the cache is bounded by the registered
// methods however many names callers send.
func getMethodPolicy(cache *sync.Map, fullMethodName string) (*pb.Policy, error) {
	if v, ok := cache.Load(fullMethodName); ok {
		return v.(*pb.Policy), nil
	}
	policy, err := lookupMethodPolicy(fullMethodName)
	if err != nil {
		return nil, err
	}
	cache.Store(fullMethodName, policy)
	return policy, nil
}

func lookupMethodPolicy(fullMethodName string) (*pb.Policy, error) {
	mm, err := parseFullMethodName(fullMethodName)
	if err != nil {
		return nil, err
	}

	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(mm.Service))
	if err != nil {
		return nil, fmt.Errorf("no descriptor for service %q: %w", mm.Service, err)
	}
	serviceDesc, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is not a service", mm.Service)
	}
	methodDesc := serviceDesc.Methods().ByName(protoreflect.Name(mm.Method))
	if methodDesc == nil {
		return nil, fmt.Errorf("no descriptor for method %q", fullMethodName)
	}

	methodOptions, ok := methodDesc.Options().(*descriptorpb.MethodOptions)
	if !ok {
		return nil, fmt.Errorf("unexpected method options type %T", methodDesc.Options())
	}
	if !proto.HasExtension(methodOptions, pb.E_Policy) {
		return nil, nil
	}
	policy, ok := proto.GetExtension(methodOptions, pb.E_Policy).(*pb.Policy)
	if !ok {
		return nil, fmt.Errorf("unexpected policy option type %T", proto.GetExtension(methodOptions, pb.E_Policy))
	}
	return policy, nil
}
