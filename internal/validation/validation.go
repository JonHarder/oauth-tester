package validation

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/JonHarder/oauth/internal/oauth/pkce"
	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
)

const AuthErrorInvalidRequest = "invalid_request"
const AuthErrorUnauthorizedClient = "unauthorized_client"
const AuthErrorAccessDenied = "access_denied"
const AuthErrorUnsupportedResponseType = "unsupported_response_type"
const AuthErrorInvalidScope = "invalid_scope"
const AuthErrorInvalidGrant = "invalid_grant"
const AuthErrorServerError = "server_error"
const AuthErrorTemporarilyUnavailable = "temporarily_unavailable"

type ValidationError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ValidateAuthhorizeRequest takes incoming parameters and creates an AuthorizeRequest.
// If there was an issue in parsing and validating, a ValidationError with information
// pertaining to the issue will be retuned.
func ValidateAuthorizeRequest(p parameters.ParameterBag, requirePkce bool) (*t.AuthorizeRequest, *ValidationError) {
	requiredParameters := []string{
		"response_type",
		"redirect_uri",
		"client_id",
		"state",
		"scope",
	}
	// Check for missing required parameters.
	for _, param := range requiredParameters {
		if !p.Has(param) {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("missing required parameter: %s", param),
			}
		}
	}

	if p.Parameters["response_type"] != "code" {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorUnsupportedResponseType,
			ErrorDescription: "server only supports response_type of 'code'",
		}
	}
	scope := p.Parameters["scope"]
	decodedScope, decodeError := url.QueryUnescape(scope)
	if decodeError != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: decodeError.Error(),
		}
	}
	scopes := strings.Split(decodedScope, " ")
	if scopes[len(scopes)-1] == "" {
		scopes = scopes[:len(scopes)-1]
	}

	pkce, err := pkce.ParsePkce(p, requirePkce)
	if err != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: err.Error(),
		}
	}

	return &t.AuthorizeRequest{
		ClientId:     p.Parameters["client_id"],
		RedirectUri:  p.Parameters["redirect_uri"],
		ResponseType: p.Parameters["response_type"],
		State:        p.Parameters["state"],
		Pkce:         pkce,
		Scopes:       scopes,
	}, nil
}
