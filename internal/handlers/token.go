package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth/grants"
)

// tokenHandler handles the /token request by exchanging the access code for an access token.
func TokenHandler(w http.ResponseWriter, req *http.Request) {
	grant, err := grants.ParseTokenRequest(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Bad token exchange request: %v", err)
		return
	}
	app, ok := db.Applications[grant.GetClientId()]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "unknown client_id")
		return
	}
	accessToken, err := grant.CreateResponse(app)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	json.NewEncoder(w).Encode(accessToken)
}
