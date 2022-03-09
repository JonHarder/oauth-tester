package validation

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
)

type AuthorizeRequest struct {
	ClientId    string
	RedirectUri string
	State       string
	Scopes      []string
}

type TokenRequest struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
	Code         t.Code
}

func ValidateAuthorizeRequest(p parameters.ParameterBag) (*AuthorizeRequest, error) {
	badAuthReq := func(missing string) error {
		return fmt.Errorf("Bad authorize request. Missing %s", missing)
	}

	redirectUri, ok := p.Parameters["redirect_uri"]
	if !ok {
		return nil, badAuthReq("redirect_uri")
	}
	clientId, ok := p.Parameters["client_id"]
	if !ok {
		return nil, badAuthReq("client_id")
	}
	state, ok := p.Parameters["state"]
	if !ok {
		return nil, badAuthReq("state")
	}
	scope, ok := p.Parameters["scope"]
	if !ok {
		return nil, badAuthReq("scope")
	}
	scopes := strings.Split(scope, " ")
	return &AuthorizeRequest{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		State:       state,
		Scopes:      scopes,
	}, nil

}

func ValidateTokenRequest(req *http.Request) (TokenRequest, error) {
	if err := req.ParseForm(); err != nil {
		return TokenRequest{}, fmt.Errorf("Error parsing form: %v", err)
	}
	clientId := req.FormValue("client_id")
	if clientId == "" {
		return TokenRequest{}, fmt.Errorf("missing required post value: client_id")
	}
	clientSecret := req.FormValue("client_secret")
	if clientSecret == "" {
		return TokenRequest{}, fmt.Errorf("missing required post value: client_secret")
	}
	redirectUri := req.FormValue("redirect_uri")
	if redirectUri == "" {
		return TokenRequest{}, fmt.Errorf("missing required post value: redirect_uri")
	}
	requestCode := req.FormValue("code")
	if requestCode == "" {
		return TokenRequest{}, fmt.Errorf("missing required post value: code")
	}

	return TokenRequest{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		RedirectUri:  redirectUri,
		Code:         t.Code(requestCode),
	}, nil
}

// verifyRedirectUri checks that the requested redirect_uri matches the one registered with the application
func VerifyRedirectUri(app t.Application, tokenReq TokenRequest) error {
	if tokenReq.RedirectUri != app.Callback {
		return fmt.Errorf(
			"provided redirect_uri: %s does not match registered uri",
			app.Callback,
		)
	}
	return nil
}
