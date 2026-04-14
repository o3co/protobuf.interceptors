package endpoint

import (
	"errors"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
)

func TestStaticVerify_ExactMatch_Allow(t *testing.T) {
	ep := NewStaticEndpoint([]StaticRule{{Resource: "posts", Action: "read"}})
	err := ep.Verify(ctxWithToken("tok"), "posts", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStaticVerify_ExactMatch_DenyWrongAction(t *testing.T) {
	ep := NewStaticEndpoint([]StaticRule{{Resource: "posts", Action: "read"}})
	err := ep.Verify(ctxWithToken("tok"), "posts", "write")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestStaticVerify_WildcardResource_MatchesAny(t *testing.T) {
	ep := NewStaticEndpoint([]StaticRule{{Resource: "*", Action: "read"}})
	err := ep.Verify(ctxWithToken("tok"), "anything", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStaticVerify_PrefixWildcard_MatchesSubpath(t *testing.T) {
	ep := NewStaticEndpoint([]StaticRule{{Resource: "posts/*", Action: "read"}})
	err := ep.Verify(ctxWithToken("tok"), "posts/123", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStaticVerify_NoToken_ReturnsUnauthenticatedError(t *testing.T) {
	ep := NewStaticEndpoint([]StaticRule{{Resource: "*", Action: "*"}})
	err := ep.Verify(ctxWithToken(""), "*", "*")
	if err == nil {
		t.Fatal("expected error")
	}
	var unauth *interceptors.UnauthenticatedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected *UnauthenticatedError, got %T: %v", err, err)
	}
}

func TestStaticVerify_NoRules_DeniesEverything(t *testing.T) {
	ep := NewStaticEndpoint(nil)
	err := ep.Verify(ctxWithToken("tok"), "anything", "read")
	if err == nil {
		t.Fatal("expected error")
	}
	var denied *interceptors.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
}

func TestMatchPattern_ExactMatch(t *testing.T) {
	if !matchPattern("posts", "posts") {
		t.Error("expected match")
	}
}

func TestMatchPattern_Star(t *testing.T) {
	if !matchPattern("*", "anything") {
		t.Error("expected match")
	}
}

func TestMatchPattern_PrefixWildcard(t *testing.T) {
	if !matchPattern("posts/*", "posts/123") {
		t.Error("expected match")
	}
}

func TestMatchPattern_PrefixWildcard_NoMatch(t *testing.T) {
	if matchPattern("posts/*", "users/123") {
		t.Error("expected no match")
	}
}
