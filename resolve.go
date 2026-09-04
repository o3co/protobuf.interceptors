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
	}

	// Substitute in one pass over the template, after every value is known.
	// Replacing mapping by mapping let a value that itself spelled
	// "<other-placeholder>" be rewritten by a later mapping, which put a
	// request field in control of a part of the resource no policy declared.
	resource, err = substituteResource(resource, fields)
	if err != nil {
		return "", "", nil, err
	}

	return resource, policy.Action, fields, nil
}

// substituteResource replaces each "<name>" in template with values[name], in a
// single left-to-right pass: substituted text is never rescanned, so a value is
// only ever data. A "<name>" with no mapping is left as written.
//
// Every substituted value is validated first — see validateResourceValue.
// Values not reached by the template are not validated: they never enter the
// resource string, and are forwarded as request context where the verifier's
// resource grammar does not apply (a DID, for instance, is all colons).
func substituteResource(template string, values map[string]string) (string, error) {
	var b strings.Builder
	b.Grow(len(template))

	for i := 0; i < len(template); {
		open := strings.IndexByte(template[i:], '<')
		if open < 0 {
			b.WriteString(template[i:])
			break
		}
		open += i

		end := strings.IndexByte(template[open+1:], '>')
		if end < 0 {
			b.WriteString(template[i:])
			break
		}
		end += open + 1

		// A '<' between this one and the '>' opens a nearer placeholder:
		// "<a<b>" names "b", as the previous replace-based implementation read it.
		if j := strings.LastIndexByte(template[open+1:end], '<'); j >= 0 {
			open = open + 1 + j
		}

		b.WriteString(template[i:open])

		name := template[open+1 : end]
		if value, ok := values[name]; ok {
			if err := validateResourceValue(name, value); err != nil {
				return "", err
			}
			b.WriteString(value)
		} else {
			b.WriteString(template[open : end+1])
		}

		i = end + 1
	}

	return b.String(), nil
}

// validateResourceValue refuses a value that would change the structure of the
// resource string rather than fill in one part of it.
//
// The accepted set is exactly one segment token of the grammar
// auth.policy-verifier's DotNotationResourceParser applies
// (packages/builtins/src/resource/DotNotationResourceParser.mts): RFC 6749
// NQCHAR — printable ASCII minus space, '"' and '\' — less the two structural
// characters '.' and ':'. In that grammar '.' separates the segments a resource
// type is built from and ':' separates a type from its id, so a value carrying
// either does not name another instance of the guarded type, it names another
// type: a policy declaring "posts:<id>" resolved with the value "1.member:2"
// produces "posts:1.member:2", read as the type "posts.member", and the rule
// that should have gated the RPC never runs.
//
// The rule lives here rather than in one endpoint because every backend — o3co,
// OPA, Cedar and the static rules — consumes the same resolved string, and
// because refusing at resolution is the only place that fails before any of
// them is asked.
//
// The set is the verifier's whole token, not just its two structural
// characters. That parser refuses the rest of them too (it never repairs its
// input), so anything outside the token is a resource string no policy can
// match; an id that needs those characters is percent-encoded by the caller,
// which round-trips through this grammar, or handled by a ResourceParser
// written for its syntax. An empty value is refused on the same footing: it
// deletes a component of the template instead of filling it.
func validateResourceValue(placeholder, value string) error {
	if value == "" {
		return &ResourceValueError{
			Placeholder: placeholder,
			Value:       value,
			Reason:      "value is empty; it would remove a component of the resource template rather than fill it",
		}
	}
	for _, r := range value {
		if !resourceValueRune(r) {
			return &ResourceValueError{
				Placeholder: placeholder,
				Value:       value,
				Reason: fmt.Sprintf(
					"value carries %q, which the resource grammar does not accept inside a segment "+
						"(printable ASCII except space, '\"', '\\', '.' and ':'); percent-encode the value to use it",
					r,
				),
			}
		}
	}
	return nil
}

// resourceValueRune reports whether r may appear in a value substituted into a
// resource template. See validateResourceValue for the grammar it mirrors.
func resourceValueRune(r rune) bool {
	switch r {
	case '.', ':': // structural: segment separator and type/id separator
		return false
	case '"', '\\': // outside NQCHAR
		return false
	}
	// Printable ASCII only: excludes control characters, space, DEL and every
	// non-ASCII rune, none of which the verifier's segment token accepts.
	return r >= 0x21 && r <= 0x7E
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
