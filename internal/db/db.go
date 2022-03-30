package db

import (
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

func init() {
	Applications = make(map[string]*t.Application)
	Users = make(map[t.Email]*t.User)
	LoginRequests = make(map[t.Code]*t.LoginRequest)
	AuthRequests = make(map[t.LoginId]t.AuthorizeRequest)
	Sessions = make(map[string]t.Session)
	RefreshTokens = make(map[string]t.RefreshRecord)
}
