package validation

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
)

type TokenRequest struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
	Code         t.Code
	CodeVerifier string
}

type ValidationError struct {
	ErrorCode        string
	ErrorDescription string
}

const AuthErrorInvalidRequest = "invalid_request"
const AuthErrorUnauthorizedClient = "unauthorized_client"
const AuthErrorAccessDenied = "access_denied"
const AuthErrorUnsupportedResponseType = "unsupported_response_type"
const AuthErrorInvalidScope = "invalid_scope"
const AuthErrorInvalidGrant = "invalid_grant"
const AuthErrorServerError = "server_error"
const AuthErrorTemporarilyUnavailable = "temporarily_unavailable"

func parsePkce(p parameters.ParameterBag, requirePkce bool) (*t.PKCE, *ValidationError) {
	var pkce *t.PKCE = nil
	codeChallenge, codeChallengeOk := p.Parameters["code_challenge"]
	if !codeChallengeOk && requirePkce {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "Server requires PKCE parameters but 'code_challenge' was not present",
		}
	}
	if codeChallengeOk {
		codeChallengeMethod := p.Get("code_challenge_method", "plain")
		pkce = &t.PKCE{
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		}
	}
	return pkce, nil
}

func ValidatePkce(pkce t.PKCE, tokenReq TokenRequest) *ValidationError {
	switch pkce.CodeChallengeMethod {
	case "S256":
		computedChallenge := util.S256CodeChallenge(tokenReq.CodeVerifier)
		if computedChallenge != pkce.CodeChallenge {
			return &ValidationError{
				ErrorCode: AuthErrorInvalidGrant,
				ErrorDescription: fmt.Sprintf(
					"PKCE computed code challenge using provided verifier: '%s' did not match challenge from auth req: %s",
					tokenReq.CodeVerifier,
					pkce.CodeChallenge,
				),
			}
		}
		break
	case "plain":
		if tokenReq.CodeVerifier != pkce.CodeChallenge {
			return &ValidationError{
				ErrorCode: AuthErrorInvalidGrant,
				ErrorDescription: fmt.Sprintf(
					"PKCE plain method verification failed, provided verifier did not match initial challenge: %s",
					tokenReq.CodeVerifier,
				),
			}
		}
		break
	default:
		return &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: fmt.Sprintf("unknown code_challenge_method: %s", pkce.CodeChallengeMethod),
		}
	}
	return nil
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
				ErrorDescription: fmt.Sprintf("missing required parameter %s", param),
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
	scopes := strings.Split(scope, " ")
	if scopes[len(scopes)-1] == "" {
		scopes = scopes[:len(scopes)-1]
	}

	pkce, err := parsePkce(p, requirePkce)
	if err != nil {
		return nil, err
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

func getBearerToken(header http.Header) (string, error) {
	bearer := header.Get("Authorization")
	if bearer == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.Split(bearer, " ")
	if parts[0] != "Bearer" {
		return "", fmt.Errorf("Authorization header is not a bearer token")
	}
	if len(parts) < 2 {
		return "", fmt.Errorf("Bearer was missing it's token")
	}
	return parts[1], nil
}

// ValidateTokenRequest
func ValidateTokenRequest(req *http.Request) (*TokenRequest, *ValidationError) {
	params, err := parameters.NewFromForm(req)
	if err != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: fmt.Sprintf("failed to parse form: %s", err.Error()),
		}
	}
	requiredParameters := []string{
		"grant_type",
		"code",
		"redirect_uri",
		"client_id",
		"code_verifier",
	}
	for _, param := range requiredParameters {
		if !params.Has(param) {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorInvalidRequest,
				ErrorDescription: "missing required parameter " + param,
			}
		}
	}

	grantType := params.Parameters["grant_type"]
	if grantType != "authorization_code" {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "invalid grant_type only 'authorization_code' allowed",
		}
	}
	clientSecret, err := getBearerToken(req.Header)
	if err != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: err.Error(),
		}
	}

	return &TokenRequest{
		ClientId:     params.Parameters["client_id"],
		ClientSecret: clientSecret,
		RedirectUri:  params.Parameters["redirect_uri"],
		Code:         t.Code(params.Parameters["code"]),
		CodeVerifier: params.Parameters["code_verifier"],
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
