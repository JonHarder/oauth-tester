package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JonHarder/oauth/internal/db"
	v "github.com/JonHarder/oauth/internal/validation"
)

// tokenHandler handles the /token request by exchanging the access code for an access token.
func TokenHandler(w http.ResponseWriter, req *http.Request) {
	tokenRequest, err := v.ValidateTokenRequest(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Bad token exchange request: %v", err)
		return
	}
	app, ok := db.Applications[tokenRequest.GetClientId()]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown client_id")
		return
	}
	accessToken, err := tokenRequest.CreateTokenResponse(*app)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(err)
		return
	}
	json.NewEncoder(w).Encode(accessToken)
}
