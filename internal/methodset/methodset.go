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

// Package methodset matches RPC method names against a set of methods and
// whole services. The gRPC and ConnectRPC verification interceptors both use
// it, so an entry means the same on either framework.
//
// The framework modules are released apart from the core and import this
// package, and a consumer may pair a released framework module with any later
// core release. So its exported API may only grow: nothing in it is removed,
// renamed, or changes meaning.
package methodset

import (
	"fmt"
	"maps"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Set is a set of RPC methods, each named as gRPC's full method name and
// ConnectRPC's procedure name it: "/package.Service/Method". An entry
// "/package.Service/" stands for every method of that service. The zero
// value is the empty set.
type Set struct {
	entries map[string]struct{}
}

// Parse returns the set of entries. Each entry is "/package.Service/Method"
// or "/package.Service/", where package.Service is a valid protobuf full name
// and Method a valid protobuf name; anything else is an error naming the
// first such entry.
func Parse(entries []string) (Set, error) {
	s := Set{entries: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		if !wellFormed(e) {
			return Set{}, fmt.Errorf("entry %q is neither /package.Service/Method nor /package.Service/", e)
		}
		s.entries[e] = struct{}{}
	}
	return s, nil
}

// wellFormed reports whether e is "/" + a protobuf full name + "/", followed
// by nothing or by a protobuf name.
func wellFormed(e string) bool {
	rest, ok := strings.CutPrefix(e, "/")
	if !ok {
		return false
	}
	service, method, ok := strings.Cut(rest, "/")
	if !ok || !protoreflect.FullName(service).IsValid() {
		return false
	}
	return method == "" || protoreflect.Name(method).IsValid()
}

// Union returns the set holding the entries of both s and o.
func (s Set) Union(o Set) Set {
	u := Set{entries: make(map[string]struct{}, len(s.entries)+len(o.entries))}
	maps.Copy(u.entries, s.entries)
	maps.Copy(u.entries, o.entries)
	return u
}

// Contains reports whether method, a full method or procedure name, is in s:
// named by an entry itself or by its service's entry.
func (s Set) Contains(method string) bool {
	i := strings.LastIndexByte(method, '/')
	if i <= 0 || i == len(method)-1 {
		return false
	}
	if _, ok := s.entries[method]; ok {
		return true
	}
	_, ok := s.entries[method[:i+1]]
	return ok
}
