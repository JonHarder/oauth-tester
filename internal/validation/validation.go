package validation

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JonHarder/oauth/internal/constants"
	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth/pkce"
	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	"github.com/golang-jwt/jwt"
)

const AuthErrorInvalidRequest = "invalid_request"
const AuthErrorUnauthorizedClient = "unauthorized_client"
const AuthErrorAccessDenied = "access_denied"
const AuthErrorUnsupportedResponseType = "unsupported_response_type"
const AuthErrorInvalidScope = "invalid_scope"
const AuthErrorInvalidGrant = "invalid_grant"
const AuthErrorServerError = "server_error"
const AuthErrorTemporarilyUnavailable = "temporarily_unavailable"

type TokenRequest interface {
	CreateTokenResponse(app t.Application) (*t.TokenResponse, *ValidationError)
	GetClientId() string
}

// Ensure each TokenRequest implementation actually implements
// the required methods of the interface
var _ TokenRequest = (*TokenAuthCodeRequest)(nil)
var _ TokenRequest = (*TokenRefreshTokenRequest)(nil)

type TokenAuthCodeRequest struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
	Code         t.Code
	CodeVerifier *string
}

type TokenRefreshTokenRequest struct {
	RefreshToken string
	ClientId     string
	ClientSecret string
}

func (req TokenRefreshTokenRequest) CreateTokenResponse(app t.Application) (*t.TokenResponse, *ValidationError) {
	if app.ClientSecret != req.ClientSecret {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorServerError,
			ErrorDescription: "invalid client_secret",
		}
	}
	refreshSession, ok := db.RefreshTokens[req.RefreshToken]
	if !ok {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorServerError,
			ErrorDescription: "unknown refresh_token",
		}
	}
	if time.Since(refreshSession.TimeGranted) > time.Second*time.Duration(8600) {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorServerError,
			ErrorDescription: "expired refresh_token",
		}
	}
	return &t.TokenResponse{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (req TokenRefreshTokenRequest) GetClientId() string {
	return req.ClientId
}

func (req TokenAuthCodeRequest) CreateTokenResponse(app t.Application) (*t.TokenResponse, *ValidationError) {
	if err := verifyRedirectUri(app, req); err != nil {
		return nil, err
	}
	loginReq, ok := db.LoginRequests[req.Code]
	if !ok {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "redirect_uri does not match the authorization request",
		}
	}
	if pk := loginReq.Pkce; pk != nil {
		if err := pkce.ValidatePkce(*pk, *req.CodeVerifier); err != nil {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorInvalidRequest,
				ErrorDescription: err.Error(),
			}
		}
	}
	if req.ClientSecret != app.ClientSecret {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "invalid client_secret",
		}
	}
	resp := t.TokenResponse{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       strings.Join(loginReq.Scopes, " "),
	}
	if loginReq.ContainsScope("openid") {
		token := generateIdToken(*loginReq, app)
		tokenStr, signingErr := token.SignedString([]byte(req.ClientSecret))
		if signingErr != nil {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorServerError,
				ErrorDescription: fmt.Sprintf("%v", signingErr),
			}
		}
		resp.IdToken = tokenStr
	}
	if loginReq.ContainsScope("offline_access") {
		resp.RefreshToken = util.RandomString(32)
		db.RefreshTokens[resp.RefreshToken] = t.RefreshRecord{
			TimeGranted: time.Now(),
			App:         app,
			User:        *loginReq.User,
		}
	}
	return &resp, nil
}

func (req TokenAuthCodeRequest) GetClientId() string {
	return req.ClientId
}

type ValidationError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func generateIdToken(loginReq t.LoginRequest, app t.Application) *jwt.Token {
	claims := jwt.MapClaims{
		"iss":         constants.ISSUER,                       // Who issued this token
		"sub":         loginReq.User.Email,                    // Identifier of the user this token represents
		"aud":         app.Name,                               // Who is this token for
		"exp":         time.Now().Add(time.Minute * 2).Unix(), // expiration time
		"iat":         time.Now().Unix(),                      // when was the token issued
		"nbf":         time.Now().Unix(),                      // time before which the token must not be accepted
		"given_name":  loginReq.User.GivenName,                // A.K.A first name
		"family_name": loginReq.User.FamilyName,               // A.K.A last name
	}
	if loginReq.Nonce != nil {
		claims["nonce"] = *loginReq.Nonce
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
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

func GetBearerToken(header http.Header) (string, error) {
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

// ValidateTokenRequest parses and validates a request for the token endpoint.
func ValidateTokenRequest(req *http.Request) (TokenRequest, *ValidationError) {
	params, err := parameters.NewFromForm(req)
	if err != nil {
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: fmt.Sprintf("failed to parse form: %s", err.Error()),
		}
	}

	grantType := params.Parameters["grant_type"]
	log.Printf("Validating Token request with grant_type: %s", grantType)
	switch grantType {
	case "refresh_token":
		requiredParams := []string{
			"client_id",
			"client_secret",
			"refresh_token",
		}
		for _, p := range requiredParams {
			if !params.Has(p) {
				return nil, &ValidationError{
					ErrorCode:        AuthErrorInvalidRequest,
					ErrorDescription: fmt.Sprintf("bad refresh_token request, missing: %s", p),
				}
			}
		}
		return TokenRefreshTokenRequest{
			RefreshToken: params.Parameters["refresh_token"],
			ClientId:     params.Parameters["client_id"],
			ClientSecret: params.Parameters["client_secret"],
		}, nil

	case "authorization_code":
		clientSecret, err := GetBearerToken(req.Header)
		if err != nil {
			return nil, &ValidationError{
				ErrorCode:        AuthErrorInvalidRequest,
				ErrorDescription: err.Error(),
			}
		}

		requiredParams := []string{
			"code",
			"redirect_uri",
			"client_id",
		}
		for _, p := range requiredParams {
			if !params.Has(p) {
				return nil, &ValidationError{
					ErrorCode:        AuthErrorInvalidRequest,
					ErrorDescription: fmt.Sprintf("Bad token request, missing query parameter: %s", p),
				}
			}
		}
		code := t.Code(params.Parameters["code"])
		var codeVerifier *string = nil
		if c := params.Parameters["code_verifier"]; c != "" {
			codeVerifier = &c
		}
		return TokenAuthCodeRequest{
			ClientId:     params.Parameters["client_id"],
			ClientSecret: clientSecret,
			RedirectUri:  params.Parameters["redirect_uri"],
			Code:         code,
			CodeVerifier: codeVerifier,
		}, nil

	default:
		return nil, &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "invalid grant_type: " + grantType,
		}
	}

}

// verifyRedirectUri checks that the requested redirect_uri matches the one registered with the application
func verifyRedirectUri(app t.Application, req TokenAuthCodeRequest) *ValidationError {
	if req.RedirectUri != app.Callback {
		return &ValidationError{
			ErrorCode:        AuthErrorInvalidRequest,
			ErrorDescription: "provided redirect_uri does not match registered uri",
		}
	}
	return nil
}
