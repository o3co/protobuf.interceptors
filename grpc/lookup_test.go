package grpc

import (
	"sync"
	"testing"

	// Importing testproto registers the service descriptor in protoregistry.GlobalFiles.
	_ "github.com/o3co/protobuf.interceptors/testproto"
)

func TestLookupMethodPolicy_WithPolicy(t *testing.T) {
	var cache sync.Map
	policy, err := getMethodPolicy(&cache, "/test.v1.TestService/GetResource")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected policy, got nil")
	}
	if policy.Resource != "resource" {
		t.Errorf("Resource = %q, want %q", policy.Resource, "resource")
	}
	if policy.Action != "read" {
		t.Errorf("Action = %q, want %q", policy.Action, "read")
	}
}

func TestLookupMethodPolicy_WithoutPolicy(t *testing.T) {
	var cache sync.Map
	policy, err := getMethodPolicy(&cache, "/test.v1.TestService/HealthCheck")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy != nil {
		t.Errorf("expected nil policy, got %+v", policy)
	}
}

// A method with no registered descriptor is an error, not "no policy", and
// is not cached: the full method name is the caller's to choose.
func TestLookupMethodPolicy_NoDescriptor_IsAnErrorAndNotCached(t *testing.T) {
	for _, method := range []string{
		"/unknown.v1.Unknown/Method",
		"/test.v1.TestService/NoSuchMethod",
		"/test.v1.GetResourceRequest/Method", // a message, not a service
	} {
		var cache sync.Map
		if _, err := getMethodPolicy(&cache, method); err == nil {
			t.Errorf("%s: expected an error", method)
		}
		cache.Range(func(k, _ any) bool {
			t.Errorf("%s: cached %v", method, k)
			return true
		})
	}
}

func TestLookupMethodPolicy_InvalidFormat(t *testing.T) {
	var cache sync.Map
	_, err := getMethodPolicy(&cache, "bad-format")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestLookupMethodPolicy_Cached(t *testing.T) {
	var cache sync.Map
	p1, _ := getMethodPolicy(&cache, "/test.v1.TestService/GetResource")
	p2, _ := getMethodPolicy(&cache, "/test.v1.TestService/GetResource")
	if p1 != p2 {
		t.Error("expected same pointer from cache")
	}
}
