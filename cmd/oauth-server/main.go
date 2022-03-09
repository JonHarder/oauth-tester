package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"

	"github.com/JonHarder/oauth/internal/handlers"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
)

const ISSUER = "oauth-test.kipsu.com"

type Config struct {
	Apps  []t.Application `json:"applications"`
	Users []t.User        `json:"users"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IdToken     string `json:"id_token"`
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
			"iss":         ISSUER,
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

// tokenHandler handles the /token request by exchanging the access code for an access token.
func tokenHandler(w http.ResponseWriter, req *http.Request) {
	tokenRequest, err := v.ValidateTokenRequest(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Bad token exchange request: %v", err)
		return
	}
	app, ok := t.Applications[tokenRequest.ClientId]
	if !ok {
		handlers.HandleBadRequest(w, req, tokenRequest.RedirectUri, "Unknown client: '%s'", tokenRequest.ClientId)
		return
	}
	if err := v.VerifyRedirectUri(*app, tokenRequest); err != nil {
		handlers.HandleBadRequest(w, req, tokenRequest.RedirectUri, "error verifying redirect_uri: %v", err)
		return
	}
	accessToken, err := generateAccessToken(app, tokenRequest)

	if err != nil {
		handlers.HandleBadRequest(w, req, tokenRequest.RedirectUri, "Invalid token exchange request: %v", err)
		return
	}

	responseBytes, err := json.Marshal(accessToken)
	if err != nil {
		handlers.HandleBadRequest(w, req, tokenRequest.RedirectUri, "encoding token response: %v", err)
		return
	}
	log.Printf("%s", string(responseBytes))
	w.Write(responseBytes)
}

// readConfig takes a path to a config.json file and parses it as a Config object.
func readConfig(path string) (*Config, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(dat, &config); err != nil {
		return nil, err
	}
	if len(config.Apps) == 0 {
		return nil, fmt.Errorf("Invalid config.json: missing or empty \"appcliatons\"")
	}
	if len(config.Users) == 0 {
		return nil, fmt.Errorf("Invalid config.json: missing or empty \"users\"")
	}
	for i, app := range config.Apps {
		if app.Callback == "" || app.ClientId == "" || app.ClientSecret == "" || app.Name == "" {
			return nil, fmt.Errorf(
				"Invalid config.json: applications[%d] is missing one of: clientId, clientSecret, callback, name",
				i,
			)
		}
	}
	for i, user := range config.Users {
		if user.Email == "" || user.Fname == "" || user.Lname == "" || user.Password == "" {
			return nil, fmt.Errorf(
				"Invalid config.json: users[%d] is missing one of: email, password, fname, lname",
				i,
			)
		}
	}
	return &config, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// main is the entry point to the oauth-server.
func main() {
	var port int
	var path string
	flag.IntVar(&port, "port", 8001, "Port to run server on")
	flag.StringVar(&path, "path", "config.json", "Configuration file containing applications and users")
	flag.Parse()

	config, err := readConfig(path)
	if err != nil {
		log.Fatalf("Error reading configuration file: %v", err)
	}
	for _, app := range config.Apps {
		t.Applications[app.ClientId] = &app
	}
	for _, u := range config.Users {
		t.Users[u.Email] = &u
	}

	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/authorize", handlers.AuthorizationHandler)
	http.HandleFunc("/token", tokenHandler)

	log.Printf("Listening on http://localhost:%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
