package grants

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth"
	"github.com/JonHarder/oauth/internal/oauth/pkce"
	p "github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
)

type Grant interface {
	CreateResponse(app *t.Application) (*t.TokenResponse, error)
	GetClientId() string
}

var _ Grant = (*AuthorizationCodeGrant)(nil)
var _ Grant = (*TokenRefreshGrant)(nil)

type AuthorizationCodeGrant struct {
	ClientId     string
	ClientSecret string
	Code         t.Code
	CodeVerifier *string
	RedirectUri  string
}

// GetClientId implements Grant
func (req *AuthorizationCodeGrant) GetClientId() string {
	return req.ClientId
}

// CreateResponse implements Grant
func (req *AuthorizationCodeGrant) CreateResponse(app *t.Application) (*t.TokenResponse, error) {
	log.Printf("Validating authorization request redirect_uri matches application")
	if req.RedirectUri != app.Callback {
		return nil, fmt.Errorf("provided redirect_uri does not match registered uri")
	}
	log.Printf("Validating a login_request exists")

	loginReq, err := db.FindLoginRequestByCode(req.Code)
	if err != nil {
		return nil, fmt.Errorf("Login request with code: '%s' not found", string(req.Code))
	}
	if pk := loginReq.Pkce; pk != nil {
		log.Printf("Validating PKCE")
		if err := pkce.ValidatePkce(*pk, *req.CodeVerifier); err != nil {
			return nil, err
		}
	}
	log.Printf("Validating client_secret")
	if req.ClientSecret != app.ClientSecret {
		log.Printf("INVALID CLIENT_SECRET!")
		return nil, fmt.Errorf("invalid client_secret")
	}
	var scopeStr string
	log.Printf("Generating scope string")
	log.Printf("from %d scopes: %v", len(loginReq.Scopes), loginReq.Scopes)
	for _, scope := range loginReq.Scopes {
		scopeStr = scopeStr + " " + scope.Name
	}
	resp := t.TokenResponse{
		RefreshToken: "",
		AccessToken:  util.RandomString(32),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        scopeStr,
		IdToken:      "",
	}
	if loginReq.ContainsScope("openid") {
		log.Printf("Generating id_token")
		token, err := oauth.GenerateIdToken(*loginReq, *app)
		if err != nil {
			return nil, err
		}
		resp.IdToken = *token
	}
	if loginReq.ContainsScope("offline_access") {
		log.Printf("Generating refresh_token")
		resp.RefreshToken = util.RandomString(32)

		refreshRecord := t.RefreshRecord{
			TimeGranted:  time.Now(),
			Application:  *app,
			User:         *loginReq.User,
			RefreshToken: resp.RefreshToken,
		}
		db.DB.Create(&refreshRecord)
	}

	session := t.Session{
		TokenResponse: resp,
		User:          *loginReq.User,
		TimeGranted:   time.Now(),
	}
	log.Printf("CreateResponse success, persisting session")
	db.DB.Create(&session)

	return &resp, nil
}

type TokenRefreshGrant struct {
	ClientId     string
	ClientSecret string
	RefreshToken string
}

// GetClientId implements Grant
func (req *TokenRefreshGrant) GetClientId() string {
	return req.ClientId
}

// CreateResponse implements Grant
func (req *TokenRefreshGrant) CreateResponse(app *t.Application) (*t.TokenResponse, error) {
	if app.ClientSecret != req.ClientSecret {
		return nil, fmt.Errorf("invalid client_secret")
	}
	var refreshRecord t.RefreshRecord
	if err := db.DB.First(&refreshRecord, "refresh_token = ?", req.RefreshToken).Error; err != nil {
		return nil, fmt.Errorf("unknown refresh_token")
	}
	if time.Since(refreshRecord.TimeGranted) > time.Second*time.Duration(8600) {
		return nil, fmt.Errorf("expired refresh_token")
	}
	return &t.TokenResponse{
		AccessToken: util.RandomString(32),
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

// ParseTokenRequest takes a request and turns it into a token object according to the grant_type.
func ParseTokenRequest(req *http.Request) (Grant, error) {
	params, err := p.NewFromForm(req)
	if err != nil {
		return nil, err
	}
	grantType := params.Get("grant_type", "")
	switch grantType {
	case "authorization_code":
		return parseAuthCodeRequest(*params, req.Header)
	case "refresh_token":
		return parseRefreshTokenRequest(*params)
	default:
		return nil, fmt.Errorf("unknown grant type: %s", grantType)
	}
}

func parseAuthCodeRequest(params p.ParameterBag, header http.Header) (Grant, error) {
	clientSecret, err := oauth.GetBearerToken(header)
	if err != nil {
		// try grabbing client secret from post params instead
		clientSecret = params.Get("client_secret", "")
		if clientSecret == "" {
			return nil, err
		}
	}
	requiredParams := []string{
		"code",
		"redirect_uri",
		"client_id",
	}
	for _, p := range requiredParams {
		if !params.Has(p) {
			return nil, fmt.Errorf("authorization_code request missing required parameter: %s", p)
		}
	}
	code := t.Code(params.Get("code", ""))
	var codeVerifier *string
	if c := params.Get("code_verifier", ""); c != "" {
		codeVerifier = &c
	}
	return &AuthorizationCodeGrant{
		ClientId:     params.Get("client_id", ""),
		ClientSecret: clientSecret,
		RedirectUri:  params.Get("redirect_uri", ""),
		Code:         code,
		CodeVerifier: codeVerifier,
	}, nil
}

func parseRefreshTokenRequest(params p.ParameterBag) (Grant, error) {
	requiredParams := []string{
		"client_id",
		"client_secret",
		"refresh_token",
	}
	for _, p := range requiredParams {
		if !params.Has(p) {
			return nil, fmt.Errorf("token_refresh request missing required parameter: %s", p)
		}
	}
	return &TokenRefreshGrant{
		RefreshToken: params.Get("refresh_token", ""),
		ClientId:     params.Get("client_id", ""),
		ClientSecret: params.Get("client_secret", ""),
	}, nil
}
