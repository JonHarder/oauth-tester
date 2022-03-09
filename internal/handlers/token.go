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
		HandleBadRequest(w, req, tokenRequest.RedirectUri, "Unknown client: '%s'", tokenRequest.ClientId)
		return
	}
	if err := v.VerifyRedirectUri(*app, tokenRequest); err != nil {
		HandleBadRequest(w, req, tokenRequest.RedirectUri, "error verifying redirect_uri: %v", err)
		return
	}
	accessToken, err := generateAccessToken(app, tokenRequest)

	if err != nil {
		HandleBadRequest(w, req, tokenRequest.RedirectUri, "Invalid token exchange request: %v", err)
		return
	}

	responseBytes, err := json.Marshal(accessToken)
	if err != nil {
		HandleBadRequest(w, req, tokenRequest.RedirectUri, "encoding token response: %v", err)
		return
	}
	log.Printf("%s", string(responseBytes))
	w.Write(responseBytes)
}

// generateAccessToken creates the access_token, including the id_token for
// OIDC requests.
func generateAccessToken(app *t.Application, tokenReq v.TokenRequest) (accessToken, error) {
	loginReq, ok := t.LoginRequests[tokenReq.Code]
	if !ok {
		return accessToken{}, fmt.Errorf("no login request with code found")
	}

	if tokenReq.ClientSecret != app.ClientSecret {
		return accessToken{}, fmt.Errorf("Invalid client_secret")
	}
	openId := false
	log.Printf("generating token based off the following scopes: %v", loginReq.Scopes)
	for _, scope := range loginReq.Scopes {
		if scope == "openid" {
			openId = true
			break
		}
	}
	resp := accessToken{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   86400,
		Scope:       strings.Join(loginReq.Scopes, " "),
	}
	if openId {
		log.Printf("Handling open id connect request")
		idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":         loginReq.User.Email,
			"aud":         app.Name,
			"iss":         constants.ISSUER,
			"sur_name":    loginReq.User.Fname,
			"family_name": loginReq.User.Lname,
		})
		tokenStr, err := idToken.SignedString([]byte(tokenReq.ClientSecret))
		if err != nil {
			return accessToken{}, err
		}
		resp.IdToken = tokenStr
	} else {
		log.Printf("Handling non open id connect request")
	}
	return resp, nil
}
