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

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ResolveResourceWithFields resolves the resource string from a Policy and an
// optional request message, and also returns a map of all extracted field values
// keyed by placeholder name. ALL field_mappings are extracted regardless of
// whether their placeholder appears in the resource template, so that callers
// can forward the values via context (e.g. subscriber_did for downstream authz).
func ResolveResourceWithFields(policy *pb.Policy, msg proto.Message) (resource, action string, fields map[string]string, err error) {
	if policy.Resource == "" {
		return "", "", nil, fmt.Errorf("policy resource must not be empty")
	}
	if policy.Action == "" {
		return "", "", nil, fmt.Errorf("policy action must not be empty")
	}

	resource = policy.Resource
	fields = make(map[string]string)

	for _, field := range policy.FieldMappings {
		if field.Placeholder == "" || field.RequestField == "" {
			return "", "", nil, fmt.Errorf("invalid field mapping: placeholder and request_field must not be empty")
		}

		if msg == nil {
			return "", "", nil, fmt.Errorf("request message is nil but field_mappings require field extraction")
		}

		value, extractErr := extractField(msg, field.RequestField)
		if extractErr != nil {
			return "", "", nil, fmt.Errorf("failed to extract field %s: %v", field.RequestField, extractErr)
		}

		fields[field.Placeholder] = value

		placeholder := fmt.Sprintf("<%s>", field.Placeholder)
		if strings.Contains(resource, placeholder) {
			resource = strings.ReplaceAll(resource, placeholder, value)
		}
	}

	return resource, policy.Action, fields, nil
}

// ResolveResource resolves the resource string from a Policy and an optional
// request message. If the policy has field_mappings, the request message is
// used to substitute placeholders in the resource template.
func ResolveResource(policy *pb.Policy, msg proto.Message) (resource, action string, err error) {
	resource, action, _, err = ResolveResourceWithFields(policy, msg)
	return
}

func extractField(msg proto.Message, fieldName string) (string, error) {
	m := msg.ProtoReflect()
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(fieldName))

	if fd == nil {
		return "", fmt.Errorf("field %s not found in request", fieldName)
	}

	if fd.IsList() || fd.IsMap() {
		return "", fmt.Errorf("field %s is list/map, unsupported", fieldName)
	}

	val := m.Get(fd)

	switch fd.Kind() {
	case protoreflect.StringKind:
		return val.String(), nil
	case protoreflect.BytesKind:
		b := val.Bytes()
		if utf8.Valid(b) {
			return string(b), nil
		}
		return hex.EncodeToString(b), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return fmt.Sprintf("%d", val.Int()), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return fmt.Sprintf("%d", val.Uint()), nil
	case protoreflect.BoolKind:
		return fmt.Sprintf("%v", val.Bool()), nil
	default:
		return "", fmt.Errorf("unsupported proto field kind %s for %s", fd.Kind(), fieldName)
	}
}
