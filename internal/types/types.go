package types

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
