package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/JonHarder/oauth/internal/config"
	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
)

// AuthorizationHandler handles the /authorize requests made by an oauth2.0 client.
// It does minimal validation, then presents the user with a login page requesting
// access on behalf of the service provider.
func AuthorizationHandler(c config.Config) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		params := parameters.NewFromQuery(req)
		authReq, err := v.ValidateAuthorizeRequest(*params, c.Settings.Pkce.Required)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%s: %s", err.ErrorCode, err.ErrorDescription)
			return
		}
		log.Printf("authorize request: %v", authReq)

		app, ok := db.Applications[authReq.ClientId]
		if !ok {
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

		serveLogin(w, *authReq, app, nil)
	}
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
	authReq, ok := db.AuthRequests[t.LoginId(loginId)]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown login request, login_id not found")
		return
	}
	code := generateCode()

	app, ok := db.Applications[authReq.ClientId]
	if !ok {
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

	u, err := validateUser(t.Email(req.FormValue("email")), req.FormValue("psw"))
	if err != nil {
		errorMsg := err.Error()
		serveLogin(w, authReq, app, &errorMsg)
		return
	}
	responseParams := url.Values{}
	nonce := util.RandomString(32)

	db.LoginRequests[code] = &t.LoginRequest{
		User:        u,
		Application: app,
		Code:        code,
		Scopes:      authReq.Scopes,
		Redirect:    authReq.RedirectUri,
		Nonce:       &nonce,
		Pkce:        authReq.Pkce,
	}

	responseParams.Set("client_id", app.ClientId)
	responseParams.Add("state", authReq.State)
	responseParams.Add("code", string(code))
	responseUrl := authReq.RedirectUri + "?" + responseParams.Encode()
	http.Redirect(w, req, responseUrl, 301)
}

// serveLogin displays the login form for the user.
// It passes oauth information through as well.
func serveLogin(w http.ResponseWriter, authorizeReq t.AuthorizeRequest, app *t.Application, e *string) {
	html := util.BinPath("static", "login.html")

	tmpl := template.Must(template.New("login.html").ParseFiles(html))
	loginId := t.LoginId(util.RandomString(32))
	db.AuthRequests[loginId] = authorizeReq
	data := struct {
		LoginId string
		Name    string
		Scopes  []string
		Error   *string
	}{
		LoginId: string(loginId),
		Name:    app.Name,
		Scopes:  authorizeReq.Scopes,
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
	u, ok := db.Users[email]
	if !ok {
		return nil, fmt.Errorf("No user with that email")
	}
	if u.Password != password {
		return nil, fmt.Errorf("Incorrect password")
	}
	return u, nil
}
