package interceptors_test

import (
	"errors"
	"strings"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	pb "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"
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

// TestResolveResource_DelegatestoWithFields verifies that ResolveResource still
// works correctly after being refactored to delegate to ResolveResourceWithFields.
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

// TestResolveResource_UnknownPlaceholderIsLeftIntact keeps the pre-existing
// behaviour: a template placeholder with no mapping stays literal.
func TestResolveResource_UnknownPlaceholderIsLeftIntact(t *testing.T) {
	policy := &pb.Policy{
		Resource: "items/<id>/<unmapped>",
		Action:   "read",
		FieldMappings: []*pb.FieldMapping{
			{Placeholder: "id", RequestField: "resource"},
		},
	}
	resource, _, err := interceptors.ResolveResource(policy, &pb.Policy{Resource: "7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != "items/7/<unmapped>" {
		t.Errorf("resource = %q, want %q", resource, "items/7/<unmapped>")
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
