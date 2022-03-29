package pkce

import (
	"testing"

	"github.com/JonHarder/oauth/internal/util"
)

func TestValidatePkceWithPlainDiffVerifierFails(t *testing.T) {
	pkce := PKCE{
		CodeChallenge:       "a",
		CodeChallengeMethod: "plain",
	}
	err := ValidatePkce(pkce, "b")
	if err == nil {
		t.Fatalf("ValidatePkce should fail when method is plain and challenge and verifier do not match")
	}
}

func TestValidatePkceWithPlainSameVerifierSuccess(t *testing.T) {
	pkce := PKCE{
		CodeChallenge:       "a",
		CodeChallengeMethod: "plain",
	}
	err := ValidatePkce(pkce, "a")
	if err != nil {
		t.Fatalf("ValidatePkce should succeed when method is plain challenge and verifier are the same")
	}
}

func TestValidatePkceWithS256VerifierSecceeds(t *testing.T) {
	verifier := "a"
	pkce := PKCE{
		CodeChallenge:       util.S256CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
	}
	err := ValidatePkce(pkce, verifier)
	if err != nil {
		t.Fatalf("ValidatePkce should succeed when method is S256 and challenge and verifier are the same")
	}
}

func TestValidatePkceWithS256DffVerifierFails(t *testing.T) {
	verifier := "a"
	pkce := PKCE{
		CodeChallenge:       util.S256CodeChallenge(verifier),
		CodeChallengeMethod: "S256",
	}
	err := ValidatePkce(pkce, "b")
	if err == nil {
		t.Fatalf("ValidatePkce should fail when method is S256 and challenge and verifier are different")
	}
}
