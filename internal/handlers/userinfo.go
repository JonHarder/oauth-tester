package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	t "github.com/JonHarder/oauth/internal/types"
)

type userInfo struct {
	Name       string `json:"name"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
	Email      string `json:"email"`
}

func UserInfoHandler(w http.ResponseWriter, req *http.Request, session t.Session) {
	if method := req.Method; method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Method '%s' not supported on userinfo endpoint", method)
	}
	user := userInfo{
		Name:       session.User.GivenName + " " + session.User.FamilyName,
		FamilyName: session.User.FamilyName,
		GivenName:  session.User.GivenName,
		Email:      string(session.User.Email),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
