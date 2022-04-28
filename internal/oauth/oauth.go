package oauth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/JonHarder/oauth/internal/constants"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/golang-jwt/jwt"
)

// GenerateIdToken generates an open id connect jwt encoded string representing the user.
// TODO: hard coded to use HS256 jwt signing method. Refactor to handle HS256 and RS256.
func GenerateIdToken(loginReq t.LoginRequest, app t.Application) (*string, error) {
	log.Printf("GenerateIdToken: user: %v", loginReq.User)
	claims := jwt.MapClaims{
		"iss":         constants.ISSUER,                       // Who issued this token
		"sub":         loginReq.User.Email,                    // Identifier of the user this token represents
		"aud":         app.ClientId,                           // Who is this token for
		"exp":         time.Now().Add(time.Minute * 2).Unix(), // expiration time
		"iat":         time.Now().Unix(),                      // when was the token issued
		"nbf":         time.Now().Unix(),                      // time before which the token must not be accepted
		"given_name":  loginReq.User.GivenName,                // A.K.A first name
		"family_name": loginReq.User.FamilyName,               // A.K.A last name
		"email":       loginReq.User.Email,
	}
	if loginReq.Nonce != nil {
		claims["nonce"] = *loginReq.Nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(app.ClientSecret))
	if err != nil {
		return nil, err
	}
	return &tokenStr, nil
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
