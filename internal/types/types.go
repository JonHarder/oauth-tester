package types

type Code string

type Email string

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

type LoginRequest struct {
	User        *User
	Application *Application
	Code        Code
	Scopes      []string
	Redirect    string
	Nonce       *string
}

var (
	Applications  map[string]*Application
	Users         map[Email]*User
	LoginRequests map[Code]*LoginRequest
)

func init() {
	Applications = make(map[string]*Application)
	Users = make(map[Email]*User)
	LoginRequests = make(map[Code]*LoginRequest)
}
