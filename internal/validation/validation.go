package validation

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
)

type AuthorizeRequest struct {
	ClientId     string
	RedirectUri  string
	ResponseType string
	State        string
	Scopes       []string
}

type TokenRequest struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
	Code         t.Code
}

const AuthErrorInvalidRequest = "invalid_request"
const AuthErrorUnauthorizedClient = "unauthorized_client"
const AuthErrorAccessDenied = "access_denied"
const AuthErrorUnsupportedResponseType = "unsupported_response_type"
const AuthErrorInvalidScope = "invalid_scope"
const AuthErrorServerError = "server_error"
const AuthErrorTemporarilyUnavailable = "temporarily_unavailable"

type ValidationError struct {
	ErrorCode        string
	ErrorDescription string
}

func notImplementedError(format string, v ...interface{}) error {
	return fmt.Errorf("Not Implemented: %s", fmt.Sprintf(format, v...))
}

func ValidateAuthorizeRequest(p parameters.ParameterBag) (*AuthorizeRequest, *ValidationError) {
	var e *ValidationError = nil

	responseType, ok := p.Parameters["response_type"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter response_type",
		}
	}
	if responseType != "code" {
		e = &ValidationError{
			ErrorCode:        AuthErrorUnsupportedResponseType,
			ErrorDescription: "server only supports response_type of 'code'",
		}
	}
	redirectUri, ok := p.Parameters["redirect_uri"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter redirect_uri",
		}
	}
	clientId, ok := p.Parameters["client_id"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter client_id",
		}
	}
	state, ok := p.Parameters["state"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter state",
		}
	}
	scope, ok := p.Parameters["scope"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter scope",
		}
	}
	scopes := strings.Split(scope, " ")
	if scopes[len(scopes)-1] == "" {
		scopes = scopes[:len(scopes)-1]
	}
	if e != nil {
		return nil, e
	}
	return &AuthorizeRequest{
		ClientId:     clientId,
		RedirectUri:  redirectUri,
		ResponseType: responseType,
		State:        state,
		Scopes:       scopes,
	}, nil
}

func ValidateTokenRequest(req *http.Request) (*TokenRequest, *ValidationError) {
	params, err := parameters.NewFromForm(req)
	var e *ValidationError = nil
	if err != nil {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "failed to parse post body",
		}
	}
	grantType, ok := params.Parameters["grant_type"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required parameter grant_type",
		}
	}
	if grantType != "authorization_code" {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "invalid grant_type only 'authorization_code' allowed",
		}
	}
	requestCode, ok := params.Parameters["code"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required post value: code",
		}
	}
	redirectUri, ok := params.Parameters["redirect_uri"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missing required post value: redirect_uri",
		}
	}
	clientId, ok := params.Parameters["client_id"]
	if !ok {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "missiong require post value: client_id",
		}
	}
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "client_secret not provided in Authorization header",
		}
	}
	authToken := strings.Split(authHeader, " ")
	var clientSecret string
	if len(authToken) < 2 {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "bad authorization header, expecting Bearer token",
		}
	} else if authToken[0] != "Bearer" {
		e = &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "bad authorization header, expecting Bearer token",
		}
	} else {
		clientSecret = authToken[1]
	}

	if e != nil {
		return nil, e
	}

	return &TokenRequest{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		RedirectUri:  redirectUri,
		Code:         t.Code(requestCode),
	}, nil
}

// verifyRedirectUri checks that the requested redirect_uri matches the one registered with the application
func VerifyRedirectUri(app t.Application, tokenReq TokenRequest) *ValidationError {
	if tokenReq.RedirectUri != app.Callback {
		return &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "provided redirect_uri does not match registered uri",
		}
	}
	return nil
}
