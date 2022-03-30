package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JonHarder/oauth/internal/db"
	v "github.com/JonHarder/oauth/internal/validation"
)

type userInfo struct {
	Name       string `json:"name"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
	Email      string `json:"email"`
}

func UserInfoHandler(w http.ResponseWriter, req *http.Request) {
	if method := req.Method; method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Method '%s' not supported on userinfo endpoint", method)
	}
	token, err := v.GetBearerToken(req.Header)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%s", err.Error())
		return
	}

	session, ok := db.Sessions[token]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "access_token not associated with active session")
		return
	}

	if session.Expired() {
		// clean up after ourselves since the token is expired
		delete(db.Sessions, token)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "access_token expired")
		return
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
