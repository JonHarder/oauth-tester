package validation

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth/pkce"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/gofiber/fiber/v2"
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
func ValidateAuthorizeRequest(c *fiber.Ctx) (*t.AuthorizeRequest, *ValidationError) {
	requiredParameters := []string{
		"response_type",
		"redirect_uri",
		"client_id",
		"state",
		"scope",
	}
	// Check for missing required parameters.
	for _, param := range requiredParameters {
		if c.FormValue(param) == "" {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("missing required parameter: %s", param),
			}
		}
	}

	if c.FormValue("response_type") != "code" {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorUnsupportedResponseType,
			ErrorDescription: "server only supports response_type of 'code'",
		}
	}
	scope := c.FormValue("scope")
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

	var allowedScopes []t.Scope
	for _, scope := range scopes {
		var s t.Scope
		if err := db.DB.First(&s, "name = ?", scope).Error; err != nil {
			log.Printf("WARNING: scope '%s' not allowed", scope)
		} else {
			allowedScopes = append(allowedScopes, s)
		}
	}

	pkce, err := pkce.ParsePkce(c)
	if err != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: err.Error(),
		}
	}

	return &t.AuthorizeRequest{
		ClientId:     c.FormValue("client_id"),
		RedirectUri:  c.FormValue("redirect_uri"),
		ResponseType: c.FormValue("response_type"),
		State:        c.FormValue("state"),
		Pkce:         pkce,
		Scopes:       allowedScopes,
	}, nil
}
