package db

import (
	"time"

	"github.com/JonHarder/oauth/internal/config"
	t "github.com/JonHarder/oauth/internal/types"
)

var (
	Applications  map[string]*t.Application
	Users         map[t.Email]*t.User
	LoginRequests map[t.Code]*t.LoginRequest
	// This is used to track an authorization request
	// while the authorization form is presented to the
	// user so that the request parameters don't need
	// to be threaded back and forth through the form
	// itself in `hidden' inputs.
	AuthRequests map[t.LoginId]t.AuthorizeRequest
	// a map of access_token to Session structs
	// this tracks users who have granted an application
	// permission to this system
	Sessions map[string]t.Session
	// a map of refresh_tokens to the the record of when it was granted.
	RefreshTokens map[string]t.RefreshRecord
)

func PersistSession(tok t.TokenResponse, user t.User) {
	Sessions[tok.AccessToken] = t.Session{
		Token:       tok,
		User:        user,
		TimeGranted: time.Now(),
	}
}

func PersistRefreshToken(refreshToken string, app t.Application, user t.User) {
	RefreshTokens[refreshToken] = t.RefreshRecord{
		TimeGranted: time.Now(),
		App:         app,
		User:        user,
	}
}

func LoadFromConfig(c config.Config) {
	for _, app := range c.Apps {
		app := app
		Applications[app.ClientId] = &app
	}
	for _, u := range c.Users {
		u := u
		Users[u.Email] = &u
	}
}

func init() {
	Applications = make(map[string]*t.Application)
	Users = make(map[t.Email]*t.User)
	LoginRequests = make(map[t.Code]*t.LoginRequest)
	AuthRequests = make(map[t.LoginId]t.AuthorizeRequest)
	Sessions = make(map[string]t.Session)
	RefreshTokens = make(map[string]t.RefreshRecord)
}
