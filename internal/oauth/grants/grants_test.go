package grants

import (
	"testing"

	"github.com/JonHarder/oauth/internal/types"
)

func TestMismatchRedirectUriFails(t *testing.T) {
	app := types.Application{
		Callback: "expected",
	}
	g := AuthorizationCodeGrant{
		RedirectUri: "wrong",
	}
	_, err := g.CreateResponse(&app)
	if err == nil {
		t.Errorf("Mismatched redirect_uri values should fail to validate")
	}
}
