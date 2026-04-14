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
