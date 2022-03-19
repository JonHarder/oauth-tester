package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/JonHarder/oauth/internal/constants"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
	"github.com/golang-jwt/jwt"
)

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IdToken     string `json:"id_token"`
}

// tokenHandler handles the /token request by exchanging the access code for an access token.
func TokenHandler(w http.ResponseWriter, req *http.Request) {
	tokenRequest, err := v.ValidateTokenRequest(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Bad token exchange request: %v", err)
		return
	}
	app, ok := t.Applications[tokenRequest.ClientId]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown client_id")
		return
	}
	if err := v.VerifyRedirectUri(*app, *tokenRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}
	accessToken, err := generateAccessToken(app, *tokenRequest)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}

	responseBytes, jsonErr := json.Marshal(accessToken)
	if jsonErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", jsonErr)
		return
	}
	log.Printf("%s", string(responseBytes))
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.Write(responseBytes)
}

// generateAccessToken creates the access_token, including the id_token for
// OIDC requests.
func generateAccessToken(app *t.Application, tokenReq v.TokenRequest) (*accessToken, *v.ValidationError) {
	loginReq, ok := t.LoginRequests[tokenReq.Code]
	if !ok {
		return nil, &v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "no login request found with provided code",
		}
	}

	if tokenReq.RedirectUri != loginReq.Redirect {
		return nil, &v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "redirect_uri does not match that of the authorization request",
		}
	}

	if pkce := loginReq.Pkce; pkce != nil {
		// TODO: this assums 'plain' code_challenge_method
		log.Printf("code_challenge: %s, code_verifier: %s", pkce.CodeChallenge, tokenReq.CodeVerifier)
		if tokenReq.CodeVerifier != pkce.CodeChallenge {
			return nil, &v.ValidationError{
				ErrorCode: v.AuthErrorInvalidGrant,
				ErrorDescription: fmt.Sprintf(
					"PKCE code_verifier using method %s failed validation",
					pkce.CodeChallengeMethod,
				),
			}
		}
	}

	if tokenReq.ClientSecret != app.ClientSecret {
		return nil, &v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "invalid client_secret",
		}
	}
	openId := false
	for _, scope := range loginReq.Scopes {
		if scope == "openid" {
			openId = true
			break
		}
	}
	log.Printf("generating access token: scopes: %v", loginReq.Scopes)
	resp := accessToken{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   86400,
		Scope:       strings.Join(loginReq.Scopes, " "),
	}
	if openId {
		claims := jwt.MapClaims{
			"iss": constants.ISSUER,
			"sub": loginReq.User.Email,
			"aud": app.Name,
			// exp expiration time
			// iat when was the token issued
			// nbf time before which the token must not be accepted
			"sur_name":    loginReq.User.Fname,
			"family_name": loginReq.User.Lname,
		}
		if loginReq.Nonce != nil {
			claims["nonce"] = *loginReq.Nonce
		}
		idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, signingErr := idToken.SignedString([]byte(tokenReq.ClientSecret))
		if signingErr != nil {
			return nil, &v.ValidationError{
				ErrorCode:        v.AuthErrorServerError,
				ErrorDescription: fmt.Sprintf("%v", signingErr),
			}
		}
		resp.IdToken = tokenStr
	}
	return &resp, nil
}
