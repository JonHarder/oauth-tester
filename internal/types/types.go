package types

import (
	"time"

	"github.com/JonHarder/oauth/internal/oauth/pkce"
)

type Code string

type Email string

// Raw data parsed from the /authorize endpoint
type AuthorizeRequest struct {
	ClientId     string
	RedirectUri  string
	ResponseType string
	State        string
	Pkce         *pkce.PKCE
	Scopes       []string
}

// Stores necessary information about which oauth
// clients are configured.
type Application struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Callback     string `json:"callback"`
	Name         string `json:"name"`
}

type User struct {
	Email      Email  `json:"email"`
	Password   string `json:"password"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
}

// Used to store information about an OAuth login
// request between the authorization step and the
// token exchange step
type LoginRequest struct {
	User        *User
	Application *Application
	Code        Code
	Scopes      []string
	Redirect    string
	Nonce       *string
	Pkce        *pkce.PKCE
}

func (req LoginRequest) ContainsScope(scope string) bool {
	for _, s := range req.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type TokenResponse struct {
	// long lived refresh_token to grant new access_tokens.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Token which grants access to the requested scopes.
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	// How many seconds the token is valid for.
	ExpiresIn int `json:"expires_in"`
	// What scopes the token was granted access to.
	Scope string `json:"scope,omitempty"`
	// OpenID Connect Id Token.
	IdToken string `json:"id_token,omitempty"`
}

type LoginId string

type Session struct {
	Token       TokenResponse
	User        User
	TimeGranted time.Time
}

func (s *Session) Expired() bool {
	return time.Since(s.TimeGranted) > time.Second*time.Duration(s.Token.ExpiresIn)
}

type RefreshRecord struct {
	TimeGranted time.Time
	App         Application
	User        User
}

var (
	Applications  map[string]*Application
	Users         map[Email]*User
	LoginRequests map[Code]*LoginRequest
	// This is used to track an authorization request
	// while the authorization form is presented to the
	// user so that the request parameters don't need
	// to be threaded back and forth through the form
	// itself in `hidden' inputs.
	AuthRequests map[LoginId]AuthorizeRequest
	// a map of access_token to Session structs
	// this tracks users who have granted an application
	// permission to this system
	Sessions map[string]Session
	// a map of refresh_tokens to the the record of when it was granted.
	RefreshTokens map[string]RefreshRecord
)

func init() {
	Applications = make(map[string]*Application)
	Users = make(map[Email]*User)
	LoginRequests = make(map[Code]*LoginRequest)
	AuthRequests = make(map[LoginId]AuthorizeRequest)
	Sessions = make(map[string]Session)
	RefreshTokens = make(map[string]RefreshRecord)
}
