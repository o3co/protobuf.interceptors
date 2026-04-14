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

type cachedPolicy struct {
	policy *pb.Policy
	err    error
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

func getMethodPolicy(cache *sync.Map, fullMethodName string) (*pb.Policy, error) {
	if v, ok := cache.Load(fullMethodName); ok {
		c := v.(*cachedPolicy)
		return c.policy, c.err
	}
	policy, err := lookupMethodPolicy(fullMethodName)
	cache.Store(fullMethodName, &cachedPolicy{policy: policy, err: err})
	return policy, err
}

func lookupMethodPolicy(fullMethodName string) (*pb.Policy, error) {
	mm, err := parseFullMethodName(fullMethodName)
	if err != nil {
		return nil, err
	}

	var serviceDesc protoreflect.ServiceDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			if string(svc.FullName()) == mm.Service {
				serviceDesc = svc
				return false
			}
		}
		return true
	})

	if serviceDesc == nil {
		return nil, nil
	}

	methodDesc := serviceDesc.Methods().ByName(protoreflect.Name(mm.Method))
	if methodDesc == nil {
		return nil, nil
	}

	opts := methodDesc.Options()
	if opts == nil {
		return nil, nil
	}

	methodOptions, ok := opts.(*descriptorpb.MethodOptions)
	if !ok {
		return nil, fmt.Errorf("unexpected method options type %T", opts)
	}

	if proto.HasExtension(methodOptions, pb.E_Policy) {
		ext := proto.GetExtension(methodOptions, pb.E_Policy)
		if policy, ok := ext.(*pb.Policy); ok {
			return policy, nil
		}
	}

	return nil, nil
}
