package types

type Code string

type Email string

// Raw data parsed from the /authorize endpoint
type AuthorizeRequest struct {
	ClientId     string
	RedirectUri  string
	ResponseType string
	State        string
	Pkce         *PKCE
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
	Email    Email  `json:"email"`
	Password string `json:"password"`
	Fname    string `json:"fname"`
	Lname    string `json:"lname"`
}

// Convience struct used to store information
// specific to the PKCE extension to the authorization
// code flow.
type PKCE struct {
	CodeChallenge       string
	CodeChallengeMethod string
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
	Pkce        *PKCE
}

type LoginId string

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
)

func init() {
	Applications = make(map[string]*Application)
	Users = make(map[Email]*User)
	LoginRequests = make(map[Code]*LoginRequest)
	AuthRequests = make(map[LoginId]AuthorizeRequest)
}
