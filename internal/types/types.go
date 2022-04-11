package types

import (
	"time"

	"github.com/JonHarder/oauth/internal/oauth/pkce"
	"gorm.io/gorm"
)

type Code string

type Email string

// Raw data parsed from the /authorize endpoint
type AuthorizeRequest struct {
	gorm.Model
	ClientId     string
	RedirectUri  string
	ResponseType string
	State        string
	Pkce         *pkce.PKCE `gorm:"embedded"`
	Scopes       []Scope    `gorm:"many2many:authreq_scopes;"`
}

type Scope struct {
	gorm.Model
	Name string
}

// Stores necessary information about which oauth
// clients are configured.
type Application struct {
	gorm.Model
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Callback     string `json:"callback"`
	Name         string `json:"name"`
}

type User struct {
	gorm.Model
	Email      Email  `json:"email"`
	Password   string `json:"password"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
}

// Used to store information about an OAuth login
// request between the authorization step and the
// token exchange step
type LoginRequest struct {
	gorm.Model
	User          *User
	UserID        uint
	Application   *Application
	ApplicationID uint
	Code          Code
	Scopes        []Scope `gorm:"many2many:loginreq_scopes;"`
	Redirect      string
	Nonce         *string
	Pkce          *pkce.PKCE `gorm:"embedded"`
}

func (req LoginRequest) ContainsScope(scope string) bool {
	for _, s := range req.Scopes {
		if s.Name == scope {
			return true
		}
	}
	return false
}

type TokenResponse struct {
	gorm.Model
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
	gorm.Model
	TokenResponse   TokenResponse
	TokenResponseID uint
	User            User
	UserID          uint
	TimeGranted     time.Time
}

func (s *Session) Expired() bool {
	return time.Since(s.TimeGranted) > time.Second*time.Duration(s.TokenResponse.ExpiresIn)
}

type RefreshRecord struct {
	gorm.Model
	TimeGranted   time.Time
	Application   Application
	ApplicationID uint
	User          User
	UserID        uint
	RefreshToken  string
}
