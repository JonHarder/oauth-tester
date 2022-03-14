package validation

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	header := make(http.Header)
	header.Set("Authorization", "Bearer super_secret")
	got, err := getBearerToken(header)
	if err != nil {
		t.Fatal(err)
	}
	expected := "super_secret"
	if got != expected {
		t.Errorf("failed to parse token out of auth header. Expecting \"%v\", got \"%v\"", expected, got)
	}
}

func TestGetBearerTokenWithMissingHeader(t *testing.T) {
	header := make(http.Header)
	_, err := getBearerToken(header)
	if err == nil {
		t.Fatalf("getBearerToken should fail when no Authorization header is present.")
	}
}

func TestGetBearerTokenWithNonBearer(t *testing.T) {
	header := make(http.Header)
	header.Set("Authorization", "foobar")
	_, err := getBearerToken(header)
	if err == nil {
		t.Fatalf("getBearerToken should fail when Authorization header is not Bearer.")
	}
}
