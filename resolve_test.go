package interceptors_test

import (
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
