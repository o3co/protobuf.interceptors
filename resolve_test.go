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
	"strings"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestResolveResource_NoFieldMappings(t *testing.T) {
	policy := &pb.Policy{Resource: "posts", Action: "read"}
	resource, action, err := interceptors.ResolveResource(policy, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "posts" {
		t.Errorf("resource = %q, want %q", resource, "posts")
	}
	if action != "read" {
		t.Errorf("action = %q, want %q", action, "read")
	}
}

func TestResolveResource_EmptyResource_ReturnsError(t *testing.T) {
	policy := &pb.Policy{Resource: "", Action: "read"}
	_, _, err := interceptors.ResolveResource(policy, nil)
	if err == nil {
		t.Fatal("expected error for empty resource")
	}
}

func TestResolveResource_EmptyAction_ReturnsError(t *testing.T) {
	policy := &pb.Policy{Resource: "posts", Action: ""}
	_, _, err := interceptors.ResolveResource(policy, nil)
	if err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestResolveResource_WithFieldMapping_StringField(t *testing.T) {
	// Use Policy itself as the request message; "resource" field is a string.
	policy := &pb.Policy{
		Resource: "items/<name>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "name", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "my-item"}
	resource, action, err := interceptors.ResolveResource(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/my-item" {
		t.Errorf("resource = %q, want %q", resource, "items/my-item")
	}
	if action != "read" {
		t.Errorf("action = %q, want %q", action, "read")
	}
}

func TestResolveResource_EmptyPlaceholder_ReturnsError(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<name>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "", RequestField: "resource"},
		},
	}
	_, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: "x"})
	if err == nil {
		t.Fatal("expected error for empty placeholder")
	}
}

func TestResolveResource_EmptyRequestField_ReturnsError(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<name>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "name", RequestField: ""},
		},
	}
	_, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: "x"})
	if err == nil {
		t.Fatal("expected error for empty request_field")
	}
}

func TestResolveResource_FieldNotFound_ReturnsError(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "nonexistent"},
		},
	}
	_, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: "x"})
	if err == nil {
		t.Fatal("expected error for nonexistent field")
	}
}

func TestResolveResource_NilMessage_WithFieldMappings_ReturnsError(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	_, _, err := interceptors.ResolveResource(policy, nil)
	if err == nil {
		t.Fatal("expected error for nil message with field_mappings")
	}
}

func TestResolveResource_AcceptsProtoMessage(t *testing.T) {
	policy := &pb.Policy{Resource: "items", Action: "read"}
	var msg proto.Message = &pb.Policy{Resource: "test"}
	resource, _, err := interceptors.ResolveResource(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items" {
		t.Errorf("resource = %q, want %q", resource, "items")
	}
}

func TestResolveResourceWithFields_NoFieldMappings(t *testing.T) {
	policy := &pb.Policy{Resource: "posts", Action: "read"}
	resource, action, fields, err := interceptors.ResolveResourceWithFields(policy, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "posts" {
		t.Errorf("resource = %q, want %q", resource, "posts")
	}
	if action != "read" {
		t.Errorf("action = %q, want %q", action, "read")
	}
	if len(fields) != 0 {
		t.Errorf("fields = %v, want empty map", fields)
	}
}

func TestResolveResourceWithFields_WithPlaceholderMapping(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<name>",
		Action:   "write",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "name", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "my-item"}
	resource, action, fields, err := interceptors.ResolveResourceWithFields(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/my-item" {
		t.Errorf("resource = %q, want %q", resource, "items/my-item")
	}
	if action != "write" {
		t.Errorf("action = %q, want %q", action, "write")
	}
	if fields["name"] != "my-item" {
		t.Errorf("fields[\"name\"] = %q, want %q", fields["name"], "my-item")
	}
}

// TestResolveResourceWithFields_ExtractsAllFieldMappings verifies that ALL
// field_mappings are extracted even if their placeholder does not appear in
// the resource template (e.g. for context-forwarding use cases).
func TestResolveResourceWithFields_ExtractsAllFieldMappings(t *testing.T) {
	policy := &pb.Policy{
		Resource: "registry.chain.peer",
		Action:   "connect",
		FieldMappings: []*pb.FieldMapping{
			// subscriber_did placeholder does NOT appear in the resource template.
			{Placeholder: "subscriber_did", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "did:example:abc"}
	resource, action, fields, err := interceptors.ResolveResourceWithFields(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "registry.chain.peer" {
		t.Errorf("resource = %q, want %q", resource, "registry.chain.peer")
	}
	if action != "connect" {
		t.Errorf("action = %q, want %q", action, "connect")
	}
	// Field must be present even though it was not used in the resource template.
	if fields["subscriber_did"] != "did:example:abc" {
		t.Errorf("fields[\"subscriber_did\"] = %q, want %q", fields["subscriber_did"], "did:example:abc")
	}
}

func TestResolveResourceWithFields_EmptyResource_ReturnsError(t *testing.T) {
	policy := &pb.Policy{Resource: "", Action: "read"}
	_, _, _, err := interceptors.ResolveResourceWithFields(policy, nil)
	if err == nil {
		t.Fatal("expected error for empty resource")
	}
}

func TestResolveResourceWithFields_NilMessage_WithFieldMappings_ReturnsError(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	_, _, _, err := interceptors.ResolveResourceWithFields(policy, nil)
	if err == nil {
		t.Fatal("expected error for nil message with field_mappings")
	}
}

// TestResolveResource_DelegatesToWithFields pins that ResolveResource
// substitutes a field mapping from the request message and returns the
// policy's action.
func TestResolveResource_DelegatesToWithFields(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<name>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "name", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "delegated-item"}
	resource, action, err := interceptors.ResolveResource(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/delegated-item" {
		t.Errorf("resource = %q, want %q", resource, "items/delegated-item")
	}
	if action != "read" {
		t.Errorf("action = %q, want %q", action, "read")
	}
}

// --- Placeholder value validation -------------------------------------------
//
// A resolved value is substituted into a string that auth.policy-verifier's
// DotNotationResourceParser (and OPA / Cedar / static rules) parse, so a value
// carrying a structural character moves the request into a different resource.
// These tests pin the refusal.

func TestResolveResource_ValueWithDot_Refused(t *testing.T) {
	policy := &pb.Policy{
		Resource: "posts:<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	// "1.member:2" turns "posts:<id>" into "posts:1.member:2", which the
	// verifier reads as resource type "posts.member".
	msg := &pb.Policy{Resource: "1.member:2"}
	resource, _, err := interceptors.ResolveResource(policy, msg)
	if err == nil {
		t.Fatalf("expected error, got resource %q", resource)
	}
}

func TestResolveResource_RefusedValue_IsADenial(t *testing.T) {
	policy := &pb.Policy{
		Resource: "posts:<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "1.member:2"}
	_, _, err := interceptors.ResolveResource(policy, msg)
	if err == nil {
		t.Fatal("expected error")
	}

	var valueErr *interceptors.ResourceValueError
	if !errors.As(err, &valueErr) {
		t.Fatalf("expected *ResourceValueError, got %T: %v", err, err)
	}
	if valueErr.Placeholder != "id" {
		t.Errorf("Placeholder = %q, want %q", valueErr.Placeholder, "id")
	}
	if valueErr.Value != "1.member:2" {
		t.Errorf("Value = %q, want %q", valueErr.Value, "1.member:2")
	}
	if strings.Contains(valueErr.Error(), valueErr.Value) {
		t.Errorf("Error() = %q, must not echo the request value back to the caller", valueErr.Error())
	}

	// Interceptors map *DeniedError to PermissionDenied; anything unmapped
	// becomes Internal. Either denies the request, but the refusal is an
	// authorization decision, not a server fault.
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected the refusal to unwrap to *DeniedError, got %T: %v", err, err)
	}
}

func TestResolveResource_RefusedValueCharacters(t *testing.T) {
	// The accepted set is exactly one token of the verifier's grammar:
	// printable ASCII except space, '"', '\', '.' and ':'.
	refused := map[string]string{
		"segment separator": "1.2",
		"id separator":      "a:b",
		"space":             "a b",
		"tab":               "a\tb",
		"newline":           "a\nb",
		"double quote":      "a\"b",
		"backslash":         "a\\b",
		"del":               "a\x7fb",
		"non-ascii":         "日本語",
		"empty":             "",
	}
	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			policy := &pb.Policy{
				Resource: "posts:<id>",
				Action:   "read",
				FieldMappings: []*pb.FieldMapping{
					{Placeholder: "id", RequestField: "resource"},
				},
			}
			resource, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: value})
			if err == nil {
				t.Fatalf("expected %q to be refused, got resource %q", value, resource)
			}
		})
	}
}

func TestResolveResource_AcceptedValueCharacters(t *testing.T) {
	// Everything the verifier's segment token allows must still resolve,
	// including '/' and the percent-encoding that is the documented escape
	// hatch for an id carrying '.' or ':'.
	accepted := map[string]string{
		"digits":          "42",
		"uuid":            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"slash":           "tenant/42",
		"percent encoded": "1%2Emember%3A2",
		"underscore":      "my_item",
		"punctuation":     "a!#$&'()*+,-;=?@[]^`{|}~<>",
	}
	for name, value := range accepted {
		t.Run(name, func(t *testing.T) {
			policy := &pb.Policy{
				Resource: "posts:<id>",
				Action:   "read",
				FieldMappings: []*pb.FieldMapping{
					{Placeholder: "id", RequestField: "resource"},
				},
			}
			resource, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: value})
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", value, err)
			}
			if want := "posts:" + value; resource != want {
				t.Errorf("resource = %q, want %q", resource, want)
			}
		})
	}
}

// TestResolveResourceWithFields_UnsubstitutedValueIsNotValidated pins the scope
// of the refusal: it applies to values that reach the resource string. A value
// only forwarded via context (a DID, which is full of ':') is untouched.
func TestResolveResourceWithFields_UnsubstitutedValueIsNotValidated(t *testing.T) {
	policy := &pb.Policy{
		Resource: "registry.chain.peer",
		Action:   "connect",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "subscriber_did", RequestField: "resource"},
		},
	}
	msg := &pb.Policy{Resource: "did:example:abc"}
	resource, _, fields, err := interceptors.ResolveResourceWithFields(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "registry.chain.peer" {
		t.Errorf("resource = %q, want %q", resource, "registry.chain.peer")
	}
	if fields["subscriber_did"] != "did:example:abc" {
		t.Errorf("fields[\"subscriber_did\"] = %q, want %q", fields["subscriber_did"], "did:example:abc")
	}
}

// TestResolveResource_SubstitutionIsSinglePass pins that a value is never
// re-scanned for placeholders: substituting <a> with a value that spells
// "<b>" must not let the b mapping rewrite it.
func TestResolveResource_SubstitutionIsSinglePass(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<a>/<b>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "a", RequestField: "resource"},
			{Placeholder: "b", RequestField: "action"},
		},
	}
	msg := &pb.Policy{Resource: "<b>", Action: "escalated"}
	resource, _, err := interceptors.ResolveResource(policy, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/<b>/escalated" {
		t.Errorf("resource = %q, want %q (a value must not be rewritten by a later mapping)",
			resource, "items/<b>/escalated")
	}
}

// A placeholder left in the template after substitution would reach the
// backend as literal text, naming a resource the policy never meant, so
// resolution fails closed. It is a server fault, not a denial: the policy is
// wrong, not the request.
func TestResolveResource_PlaceholderLeftInTheTemplate_IsAnError(t *testing.T) {
	for name, tc := range map[string]struct {
		policy *pb.Policy
		msg    proto.Message
	}{
		"unmapped placeholder": {
			policy: &pb.Policy{
				Resource: "items/<id>/<unmapped>",
				Action:   "read",
				FieldMappings: []*pb.FieldMapping{
					{Placeholder: "id", RequestField: "resource"},
				},
			},
			msg: &pb.Policy{Resource: "7"},
		},
		"misspelled placeholder": {
			policy: &pb.Policy{
				Resource: "items/<idd>",
				Action:   "read",
				FieldMappings: []*pb.FieldMapping{
					{Placeholder: "id", RequestField: "resource"},
				},
			},
			msg: &pb.Policy{Resource: "7"},
		},
		"no field_mappings at all": {
			policy: &pb.Policy{Resource: "items/<id>", Action: "read"},
		},
	} {
		resource, _, err := interceptors.ResolveResource(tc.policy, tc.msg)
		if err == nil {
			t.Errorf("%s: resolved to %q, want an error", name, resource)
			continue
		}
		var denied *interceptors.DeniedError
		if errors.As(err, &denied) {
			t.Errorf("%s: error %v is a denial, want a server fault", name, err)
		}
	}
}

// A bytes field is always hex-encoded, so two different values never resolve
// to the same resource: 0xff and the two bytes "ff" are distinct.
func TestResolveResource_BytesFieldIsHexEncoded(t *testing.T) {
	policy := &pb.Policy{
		Resource: "blobs/<b>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "b", RequestField: "value"},
		},
	}
	for _, tc := range []struct {
		value []byte
		want  string
	}{
		{[]byte{0xff}, "blobs/ff"},
		{[]byte("ff"), "blobs/6666"},
	} {
		resource, _, err := interceptors.ResolveResource(policy, wrapperspb.Bytes(tc.value))
		if err != nil {
			t.Fatalf("value %x: unexpected error: %v", tc.value, err)
		}
		if resource != tc.want {
			t.Errorf("value %x: resource = %q, want %q", tc.value, resource, tc.want)
		}
	}
}

func TestResolveResource_RepeatedPlaceholderIsSubstitutedEverywhere(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<id>/mirror/<id>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	resource, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: "7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/7/mirror/7" {
		t.Errorf("resource = %q, want %q", resource, "items/7/mirror/7")
	}
}

// nestedMessages builds, from descriptors, a request type with nested
// messages:
//
//	message Request {
//	  Post post = 1;
//	  repeated Post posts = 2;
//	  string id = 3;
//	  map<string, Post> by_key = 4;
//	  oneof target { Post featured = 5; Author guest = 6; }
//	}
//	message Post { string name = 1; Author author = 2; bytes digest = 3; int64 rank = 4; }
//	message Author { string id = 1; }
func nestedMessages(t *testing.T) (request, post, author protoreflect.MessageDescriptor) {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	field := func(name string, number int32, label *descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name:     proto.String(name),
			JsonName: proto.String(name),
			Number:   proto.Int32(number),
			Label:    label,
			Type:     typ.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	inOneof := func(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
		f.OneofIndex = proto.Int32(0)
		return f
	}
	msgType := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("nested_request_test.proto"),
		Package: proto.String("nestedtest"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Request"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("post", 1, optional, msgType, ".nestedtest.Post"),
					field("posts", 2, repeated, msgType, ".nestedtest.Post"),
					field("id", 3, optional, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					field("by_key", 4, repeated, msgType, ".nestedtest.Request.ByKeyEntry"),
					inOneof(field("featured", 5, optional, msgType, ".nestedtest.Post")),
					inOneof(field("guest", 6, optional, msgType, ".nestedtest.Author")),
				},
				OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("target")}},
				NestedType: []*descriptorpb.DescriptorProto{{
					Name: proto.String("ByKeyEntry"),
					Field: []*descriptorpb.FieldDescriptorProto{
						field("key", 1, optional, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
						field("value", 2, optional, msgType, ".nestedtest.Post"),
					},
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				}},
			},
			{
				Name: proto.String("Post"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("name", 1, optional, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					field("author", 2, optional, msgType, ".nestedtest.Author"),
					field("digest", 3, optional, descriptorpb.FieldDescriptorProto_TYPE_BYTES, ""),
					field("rank", 4, optional, descriptorpb.FieldDescriptorProto_TYPE_INT64, ""),
				},
			},
			{
				Name: proto.String("Author"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("id", 1, optional, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("building test descriptors: %v", err)
	}
	msgs := fd.Messages()
	return msgs.ByName("Request"), msgs.ByName("Post"), msgs.ByName("Author")
}

// nestedRequest returns a Request whose post has the given name and, when
// authorID is not empty, an author with that id. An empty name leaves post
// unset.
func nestedRequest(t *testing.T, name, authorID string) proto.Message {
	t.Helper()
	reqDesc, postDesc, authorDesc := nestedMessages(t)
	req := dynamicpb.NewMessage(reqDesc)
	if name == "" {
		return req
	}
	post := dynamicpb.NewMessage(postDesc)
	post.Set(postDesc.Fields().ByName("name"), protoreflect.ValueOfString(name))
	if authorID != "" {
		author := dynamicpb.NewMessage(authorDesc)
		author.Set(authorDesc.Fields().ByName("id"), protoreflect.ValueOfString(authorID))
		post.Set(postDesc.Fields().ByName("author"), protoreflect.ValueOfMessage(author))
	}
	req.Set(reqDesc.Fields().ByName("post"), protoreflect.ValueOfMessage(post))
	return req
}

func nestedPolicy(resource, requestField string) *pb.Policy {
	return &pb.Policy{
		Resource:      resource,
		Action:        "read",
		FieldMappings: []*pb.FieldMapping{{Placeholder: "v", RequestField: requestField}},
	}
}

func TestResolveResource_NestedPath_Resolves(t *testing.T) {
	for _, tc := range []struct {
		path, want string
	}{
		{"post.name", "posts/hello"},
		{"post.author.id", "posts/alice"},
	} {
		resource, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", tc.path), nestedRequest(t, "hello", "alice"))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.path, err)
		}
		if resource != tc.want {
			t.Errorf("%s: resource = %q, want %q", tc.path, resource, tc.want)
		}
	}
}

// The leaf of a path behaves as a top-level field does: the segment grammar
// applies to its substituted value, and an unset scalar leaf is its zero value.
func TestResolveResource_NestedPath_LeafIsATopLevelField(t *testing.T) {
	_, _, err := interceptors.ResolveResource(nestedPolicy("posts:<v>", "post.name"), nestedRequest(t, "1.member:2", ""))
	var valueErr *interceptors.ResourceValueError
	if !errors.As(err, &valueErr) || valueErr.Value != "1.member:2" {
		t.Errorf("err = %v, want a *ResourceValueError for the leaf value", err)
	}

	resource, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", "post.rank"), nestedRequest(t, "set", ""))
	if err != nil || resource != "posts/0" {
		t.Errorf("unset int64 leaf: resource, err = %q, %v; want %q, nil", resource, err, "posts/0")
	}

	_, _, err = interceptors.ResolveResource(nestedPolicy("posts/<v>", "post.digest"), nestedRequest(t, "set", ""))
	if !errors.As(err, &valueErr) {
		t.Errorf("unset bytes leaf: err = %v, want a *ResourceValueError for an empty value", err)
	}
}

// A message the request left unset on the way is refused as a denial: the
// caller decides whether it is set, so it must never resolve to a zero value.
func TestResolveResource_NestedPath_UnsetParent_IsADenial(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		msg        proto.Message
	}{
		{"unset first message", "post.name", nestedRequest(t, "", "")},
		{"unset inner message", "post.author.id", nestedRequest(t, "hello", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", tc.path), tc.msg)
			var valueErr *interceptors.ResourceValueError
			if !errors.As(err, &valueErr) {
				t.Fatalf("err = %v (%T), want *ResourceValueError", err, err)
			}
			if valueErr.Placeholder != "v" {
				t.Errorf("Placeholder = %q, want %q", valueErr.Placeholder, "v")
			}
			var denied *interceptors.DeniedError
			if !errors.As(err, &denied) {
				t.Errorf("err = %v, want one that unwraps to *DeniedError", err)
			}
		})
	}
}

// A path that cannot be walked is the policy's mistake, not the caller's: it
// is an error that is not a denial, which the interceptors map to Internal.
func TestResolveResource_NestedPath_Unwalkable_IsNotADenial(t *testing.T) {
	for _, path := range []string{
		"posts.name",  // repeated in the middle
		"by_key.name", // map in the middle
		"post.title",  // unknown leaf
		"article.name",
		"id.value", // a scalar in the middle
		"post",     // a message leaf
		"post.",
		".post",
		"post..name",
	} {
		t.Run(path, func(t *testing.T) {
			_, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", path), nestedRequest(t, "hello", "alice"))
			if err == nil {
				t.Fatal("expected an error")
			}
			var denied *interceptors.DeniedError
			if errors.As(err, &denied) {
				t.Errorf("err = %v is a denial, want an error that maps to Internal", err)
			}
		})
	}
}

// A mapping whose placeholder the template does not use is still extracted
// along its path, and forwarded without the segment grammar.
func TestResolveResourceWithFields_NestedPath_ForwardedOnly(t *testing.T) {
	policy := &pb.Policy{
		Resource: "posts",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "author", RequestField: "post.author.id"},
		},
	}
	resource, _, fields, err := interceptors.ResolveResourceWithFields(policy, nestedRequest(t, "hello", "did:example:alice"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "posts" {
		t.Errorf("resource = %q, want %q", resource, "posts")
	}
	if got := fields["author"]; got != "did:example:alice" {
		t.Errorf("fields[author] = %q, want %q", got, "did:example:alice")
	}

	// Its unset parent is refused all the same.
	_, _, _, err = interceptors.ResolveResourceWithFields(policy, nestedRequest(t, "hello", ""))
	var valueErr *interceptors.ResourceValueError
	if !errors.As(err, &valueErr) {
		t.Errorf("err = %v, want *ResourceValueError", err)
	}
}

// A oneof member is unset when another member is set, and is refused as any
// unset message is.
func TestResolveResource_NestedPath_OtherOneofMemberSet_IsADenial(t *testing.T) {
	reqDesc, _, authorDesc := nestedMessages(t)
	req := dynamicpb.NewMessage(reqDesc)
	guest := dynamicpb.NewMessage(authorDesc)
	guest.Set(authorDesc.Fields().ByName("id"), protoreflect.ValueOfString("alice"))
	req.Set(reqDesc.Fields().ByName("guest"), protoreflect.ValueOfMessage(guest))

	_, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", "featured.name"), req)
	var valueErr *interceptors.ResourceValueError
	if !errors.As(err, &valueErr) {
		t.Errorf("err = %v (%T), want *ResourceValueError", err, err)
	}
}

// A path the request type cannot have is the policy's mistake whether or not
// the request set the messages on it: it is never reported as a denial.
func TestResolveResource_NestedPath_UnwalkableBehindUnsetParent_IsNotADenial(t *testing.T) {
	for _, path := range []string{
		"post.title",
		"post.",
		"post.name.value",
		"post.author",
		"post.author.id.x",
		"post.author.name",
	} {
		t.Run(path, func(t *testing.T) {
			_, _, err := interceptors.ResolveResource(nestedPolicy("posts/<v>", path), nestedRequest(t, "", ""))
			if err == nil {
				t.Fatal("expected an error")
			}
			var denied *interceptors.DeniedError
			if errors.As(err, &denied) {
				t.Errorf("err = %v is a denial, want an error that maps to Internal", err)
			}
		})
	}
}
