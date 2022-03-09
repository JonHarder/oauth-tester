package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"
)

// handleAuthorizeRequest handles the /authorize requests made by an oauth2.0 client.
// It does minimal validation, then presents the user with a login page requesting
// access on behalf of the service provider.
func AuthorizationHandler(w http.ResponseWriter, req *http.Request) {
	params := parameters.NewFromQuery(req)
	authReq, err := v.ValidateAuthorizeRequest(*params)
	if err != nil {
		HandleBadRequest(w, req, req.Host, "Bad authorization request: %v", err)
		return
	}
	log.Printf("authorize request: %v", authReq)

	app, ok := t.Applications[authReq.ClientId]
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
	authReq, err := v.ValidateAuthorizeRequest(*params)
	code := generateCode()

	app, ok := t.Applications[authReq.ClientId]
	if !ok {
		HandleBadRequest(w, req, authReq.RedirectUri, "Unknown client_id")
		return
	}

	u, err := validateUser(t.Email(req.FormValue("email")), req.FormValue("psw"))
	if err != nil {
		errorMsg := err.Error()
		serveLogin(w, *authReq, app, &errorMsg)
		return
	}
	responseParams := url.Values{}
	t.LoginRequests[code] = &t.LoginRequest{
		User:        u,
		Application: app,
		Code:        code,
		Scopes:      authReq.Scopes,
	}

	responseParams.Set("client_id", app.ClientId)
	responseParams.Add("state", authReq.State)
	responseParams.Add("code", string(code))
	responseUrl := authReq.RedirectUri + "?" + responseParams.Encode()
	http.Redirect(w, req, responseUrl, 301)
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

func generateCode() t.Code {
	return t.Code(util.RandomString(32))
}

// validateUser confirms the user with provided credentials exists.
func validateUser(email t.Email, password string) (*t.User, error) {
	u, ok := t.Users[email]
	if !ok {
		return nil, fmt.Errorf("No user with that email")
	}
	if u.Password != password {
		return nil, fmt.Errorf("Incorrect password")
	}
	return u, nil
}
