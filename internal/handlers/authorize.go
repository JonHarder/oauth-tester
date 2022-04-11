package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth"
	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
)

// AuthorizationHandler handles the /authorize requests made by an oauth2.0 client.
// It does minimal validation, then presents the user with a login page requesting
// access on behalf of the service provider.
func AuthorizationHandler(w http.ResponseWriter, req *http.Request) {
	params := parameters.NewFromQuery(req)
	authReq, err := v.ValidateAuthorizeRequest(*params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%s: %s", err.ErrorCode, err.ErrorDescription)
		return
	}
	log.Printf("authorize request: %v", authReq)

	var app t.Application
	if err := db.DB.First(&app, "client_id = ?", authReq.ClientId).Error; err != nil {
		HandleBadRequest(w, req, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorUnauthorizedClient,
			ErrorDescription: fmt.Sprintf("No client configured with ID: %s", authReq.ClientId),
		})
		return
	}

	if app.Callback != authReq.RedirectUri {
		HandleBadRequest(w, req, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "token reqirect_uri does not match authorization request",
		})
		return
	}

	serveLogin(w, *authReq, &app, nil)
}

// loginHandler processes the login after the user logs in.
// This endpoint is hit internally after the /authorization endpoint
// serves the login form.
// After successful generation of the authorization code, the user
// is redirected to their specified callback url.
func LoginHandler(w http.ResponseWriter, req *http.Request) {
	params, err := parameters.NewFromForm(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid post body. expecting content type 'application/x-www-urnencoded'")
		return
	}
	loginId, ok := params.Parameters["login_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "missing login_id")
		return
	}
	authReq, ok := loginIds[t.LoginId(loginId)]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown login request, login_id not found")
		return
	}

	var app t.Application
	if err := db.DB.First(&app, "client_id = ?", authReq.ClientId).Error; err != nil {
		HandleBadRequest(w, req, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "unknown client_id",
		})
		return
	}

	if app.Callback != authReq.RedirectUri {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Callback does not match registered redirect uri")
		return
	}
	responseParams := url.Values{}
	responseParams.Set("state", authReq.State)
	responseParams.Set("client_id", app.ClientId)

	u, err := validateUser(t.Email(req.FormValue("email")), req.FormValue("psw"))
	if err != nil {
		errorMsg := err.Error()
		serveLogin(w, *authReq, &app, &errorMsg)
		return
	}

	nonce := util.RandomString(32)

	loginReq := &t.LoginRequest{
		User:        u,
		Application: &app,
		Scopes:      authReq.Scopes,
		Redirect:    authReq.RedirectUri,
		Nonce:       &nonce,
		Pkce:        authReq.Pkce,
	}

	responseTypes := strings.Split(authReq.ResponseType, " ")
	for _, responseType := range responseTypes {
		if responseType == "code" {
			code := generateCode()
			loginReq.Code = code
			log.Printf("Persisting login_request")
			db.DB.Create(loginReq)
			responseParams.Set("code", string(code))
		}
		if responseType == "token" {
			accessToken := util.RandomString(32)
			responseParams.Set("token", accessToken)

			var scopeStr string
			for _, scope := range authReq.Scopes {
				scopeStr = scopeStr + " " + scope.Name
			}
			tokenResp := t.TokenResponse{
				AccessToken: accessToken,
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       scopeStr,
			}
			session := t.Session{
				TokenResponse: tokenResp,
				User:          *u,
				TimeGranted:   time.Now(),
			}
			db.DB.Create(&session)
		}
		if responseType == "id_token" {
			idToken, err := oauth.GenerateIdToken(*loginReq, app)
			if err != nil {
				log.Printf("Error generating id_token in authorization request: %v", err)
			}
			responseParams.Set("id_token", *idToken)
		}
	}

	responseUrl := authReq.RedirectUri + "?" + responseParams.Encode()
	http.Redirect(w, req, responseUrl, 301)
}

var loginIds map[t.LoginId]*t.AuthorizeRequest = make(map[t.LoginId]*t.AuthorizeRequest)

// serveLogin displays the login form for the user.
// It passes oauth information through as well.
func serveLogin(w http.ResponseWriter, authorizeReq t.AuthorizeRequest, app *t.Application, e *string) {
	html := util.BinPath("static", "login.html")

	tmpl := template.Must(template.New("login.html").ParseFiles(html))
	loginId := t.LoginId(util.RandomString(32))
	loginIds[loginId] = &authorizeReq

	db.DB.Create(&authorizeReq)
	var scopes []string
	for _, scope := range authorizeReq.Scopes {
		scopes = append(scopes, scope.Name)
	}
	data := struct {
		LoginId string
		Name    string
		Scopes  []string
		Error   *string
	}{
		LoginId: string(loginId),
		Name:    app.Name,
		Scopes:  scopes,
		Error:   e,
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("ERROR: executing template: %v", err)
		fmt.Fprintf(w, "ERROR: executing template: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func generateCode() t.Code {
	return t.Code(util.RandomString(32))
}

// validateUser confirms the user with provided credentials exists.
func validateUser(email t.Email, password string) (*t.User, error) {
	var user t.User
	if err := db.DB.First(&user, "email = ?", string(email)).Error; err != nil {
		return nil, fmt.Errorf("No user with that email")
	}
	if user.Password != password {
		return nil, fmt.Errorf("Incorrect password")
	}
	return &user, nil
}
