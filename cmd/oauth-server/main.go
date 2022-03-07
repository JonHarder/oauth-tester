package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"

	"github.com/JonHarder/oauth/internal/parameters"
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

type loginRequest struct {
	user        *t.User
	application *t.Application
	code        v.Code
	scopes      []string
}

var (
	applications  map[string]*t.Application
	users         map[t.Email]*t.User
	loginRequests map[v.Code]*loginRequest
)

func generateCode() v.Code {
	return v.Code(util.RandomString(32))
}

// handleBadRequest generates an error response to the callback.
// Redirects back to redirect_uri with error query parameter set
func handleBadRequest(w http.ResponseWriter, req *http.Request, redirect string, format string, vars ...interface{}) {
	parameters := url.Values{}
	parameters.Set("error", fmt.Sprintf(format, vars...))
	u := redirect + "?" + parameters.Encode()
	log.Printf("Redirecting to %s", u)
	http.Redirect(w, req, u, 301)
}

// validateUser confirms the user with provided credentials exists.
func validateUser(email t.Email, password string) (*t.User, error) {
	u, ok := users[email]
	if !ok {
		return nil, fmt.Errorf("No user with that email")
	}
	if u.Password != password {
		return nil, fmt.Errorf("Incorrect password")
	}
	return u, nil
}

// serveLogin displays the login form for the user.
// It passes oauth information through as well.
func serveLogin(w http.ResponseWriter, authorizeReq v.AuthorizeRequest, app *t.Application, e *string) {
	tmpl, err := template.New("login.html").ParseFiles("login.html")
	if err != nil {
		log.Printf("ERROR: parsing template: %v", err)
		fmt.Fprintf(w, "ERROR: parsing template: %v", err)
		return
	}
	data := struct {
		ClientId    string
		RedirectUri string
		State       string
		Scopes      []string
		Name        string
		Error       *string
	}{
		ClientId:    authorizeReq.ClientId,
		RedirectUri: authorizeReq.RedirectUri,
		State:       authorizeReq.State,
		Scopes:      authorizeReq.Scopes,
		Name:        app.Name,
		Error:       e,
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("ERROR: executing template: %v", err)
		fmt.Fprintf(w, "ERROR: executing template: %v", err)
	}
}

// loginHandler processes the login after the user logs in.
// This endpoint is hit internally after the /authorization endpoint
// serves the login form.
// After successful generation of the authorization code, the user
// is redirected to their specified callback url.
func loginHandler(w http.ResponseWriter, req *http.Request) {
	params, err := parameters.NewFromForm(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid post body. expecting content type 'application/x-www-urnencoded'")
		return
	}
	authReq, err := v.ValidateAuthorizeRequest(*params)
	code := generateCode()

	app, ok := applications[authReq.ClientId]
	if !ok {
		handleBadRequest(w, req, authReq.RedirectUri, "Unknown client_id")
		return
	}

	u, err := validateUser(t.Email(req.FormValue("email")), req.FormValue("psw"))
	if err != nil {
		errorMsg := err.Error()
		serveLogin(w, *authReq, app, &errorMsg)
		return
	}
	responseParams := url.Values{}
	loginRequests[code] = &loginRequest{
		user:        u,
		application: app,
		code:        code,
		scopes:      authReq.Scopes,
	}

	responseParams.Set("client_id", app.ClientId)
	responseParams.Add("state", authReq.State)
	responseParams.Add("code", string(code))
	responseUrl := authReq.RedirectUri + "?" + responseParams.Encode()
	http.Redirect(w, req, responseUrl, 301)
}

// handleAuthorizeRequest handles the /authorize requests made by an oauth2.0 client
// It does minimal validation, then presents the user with a login page requesting
// access on behalf of the service provider.
func authorizationHandler(w http.ResponseWriter, req *http.Request) {
	params := parameters.NewFromQuery(req)
	authReq, err := v.ValidateAuthorizeRequest(*params)
	if err != nil {
		handleBadRequest(w, req, req.Host, "Bad authorization request: %v", err)
		return
	}
	log.Printf("authorize request: %v", authReq)

	app, ok := applications[authReq.ClientId]
	if !ok {
		fmt.Fprintf(w, "No client configured with ID: %s", authReq.ClientId)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if app.Callback != authReq.RedirectUri {
		fmt.Fprintf(w, "Invalid redirect_uri %s", authReq.RedirectUri)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	serveLogin(w, *authReq, app, nil)
}

// generateAccessToken creates the access_token, including the id_token for
// OIDC requests.
func generateAccessToken(app *t.Application, tokenReq v.TokenRequest) (accessToken, error) {
	loginReq, ok := loginRequests[tokenReq.Code]
	if !ok {
		return accessToken{}, fmt.Errorf("no login request with code found")
	}

	if tokenReq.ClientSecret != app.ClientSecret {
		return accessToken{}, fmt.Errorf("Invalid client_secret")
	}
	openId := false
	log.Printf("generating token based off the following scopes: %v", loginReq.scopes)
	for _, scope := range loginReq.scopes {
		if scope == "openid" {
			openId = true
			break
		}
	}
	resp := accessToken{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   86400,
		Scope:       strings.Join(loginReq.scopes, " "),
	}
	if openId {
		log.Printf("Handling open id connect request")
		idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":         loginReq.user.Email,
			"aud":         app.Name,
			"iss":         ISSUER,
			"sur_name":    loginReq.user.Fname,
			"family_name": loginReq.user.Lname,
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
	app, ok := applications[tokenRequest.ClientId]
	if !ok {
		handleBadRequest(w, req, tokenRequest.RedirectUri, "Unknown client: '%s'", tokenRequest.ClientId)
		return
	}
	if err := v.VerifyRedirectUri(*app, tokenRequest); err != nil {
		handleBadRequest(w, req, tokenRequest.RedirectUri, "error verifying redirect_uri: %v", err)
		return
	}
	accessToken, err := generateAccessToken(app, tokenRequest)

	if err != nil {
		handleBadRequest(w, req, tokenRequest.RedirectUri, "Invalid token exchange request: %v", err)
		return
	}

	responseBytes, err := json.Marshal(accessToken)
	if err != nil {
		handleBadRequest(w, req, tokenRequest.RedirectUri, "encoding token response: %v", err)
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
	return &config, nil
}

func init() {
	applications = make(map[string]*t.Application)
	users = make(map[t.Email]*t.User)
	loginRequests = make(map[v.Code]*loginRequest)
	rand.Seed(time.Now().UnixNano())
}

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
		applications[app.ClientId] = &app
	}
	for _, u := range config.Users {
		users[u.Email] = &u
	}

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authorize", authorizationHandler)
	http.HandleFunc("/token", tokenHandler)

	log.Printf("Listening on http://localhost:%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
