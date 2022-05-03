package handlers

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	v "github.com/JonHarder/oauth/internal/validation"

	"github.com/gofiber/fiber/v2"
)

// AuthorizationHandler handles the /authorize requests made by an oauth2.0 client.
// It does minimal validation, then presents the user with a login page requesting
// access on behalf of the service provider.
func AuthorizationHandler(c *fiber.Ctx) error {
	authReq, err := v.ValidateAuthorizeRequest(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString(fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription))
	}
	log.Printf("authorize request: %v", authReq)

	var app t.Application
	if err := db.DB.First(&app, "client_id = ?", authReq.ClientId).Error; err != nil {
		return HandleBadRequest(c, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorUnauthorizedClient,
			ErrorDescription: fmt.Sprintf("No client configured with ID: %s", authReq.ClientId),
		})
	}

	if app.Callback != authReq.RedirectUri {
		return HandleBadRequest(c, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "token reqirect_uri does not match authorization request",
		})
	}

	return serveLogin(c, *authReq, &app, nil)
}

// loginHandler processes the login after the user logs in.
// This endpoint is hit internally after the /authorization endpoint
// serves the login form.
// After successful generation of the authorization code, the user
// is redirected to their specified callback url.
func LoginHandler(c *fiber.Ctx) error {
	loginId := c.FormValue("login_id")
	if loginId == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing login_id")
	}
	authReq, ok := loginIds[t.LoginId(loginId)]
	if !ok {
		return c.Status(fiber.StatusBadRequest).SendString("unknown login request, login_id not found")
	}

	var app t.Application
	if err := db.DB.First(&app, "client_id = ?", authReq.ClientId).Error; err != nil {
		return HandleBadRequest(c, authReq.RedirectUri, v.ValidationError{
			ErrorCode:        v.AuthErrorInvalidRequest,
			ErrorDescription: "unknown client_id",
		})
	}

	if app.Callback != authReq.RedirectUri {
		return c.Status(fiber.StatusForbidden).SendString("Callback does not match registered redirect uri")
	}
	responseParams := url.Values{}
	responseParams.Set("state", authReq.State)
	responseParams.Set("client_id", app.ClientId)

	u, err := validateUser(t.Email(c.FormValue("email")), c.FormValue("psw"))
	if err != nil {
		errorMsg := err.Error()
		return serveLogin(c, *authReq, &app, &errorMsg)
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
	return c.Redirect(responseUrl, 301)
}

var loginIds map[t.LoginId]*t.AuthorizeRequest = make(map[t.LoginId]*t.AuthorizeRequest)

// serveLogin displays the login form for the user.
// It passes oauth information through as well.
func serveLogin(c *fiber.Ctx, authorizeReq t.AuthorizeRequest, app *t.Application, e *string) error {
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
	return c.Render("login", data)
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
