package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/JonHarder/oauth/internal/constants"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
	"github.com/golang-jwt/jwt"
)

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
		fmt.Fprintf(w, "%s: %s", err.ErrorCode, err.ErrorDescription)
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
func generateAccessToken(app *t.Application, tokenReq v.TokenRequest) (*t.TokenResponse, *v.ValidationError) {
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
		err := v.ValidatePkce(*pkce, tokenReq)
		if err != nil {
			return nil, err
		}
	}

	if tokenReq.ClientSecret != app.ClientSecret {
		return nil, &v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "invalid client_secret",
		}
	}
	openId := loginReq.ContainsScope("openid")
	log.Printf("generating access token: scopes: %v", loginReq.Scopes)
	resp := t.TokenResponse{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   86400,
		Scope:       strings.Join(loginReq.Scopes, " "),
	}
	t.Sessions[resp.AccessToken] = t.Session{
		Token:       resp,
		User:        *loginReq.User,
		TimeGranted: time.Now(),
	}
	if openId {
		claims := jwt.MapClaims{
			"iss":         constants.ISSUER,                       // Who issued this token
			"sub":         loginReq.User.Email,                    // Identifier of the user this token represents
			"aud":         app.Name,                               // Who is this token for
			"exp":         time.Now().Add(time.Minute * 2).Unix(), // expiration time
			"iat":         time.Now().Unix(),                      // when was the token issued
			"nbf":         time.Now().Unix(),                      // time before which the token must not be accepted
			"given_name":  loginReq.User.GivenName,
			"family_name": loginReq.User.FamilyName,
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