package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth/grants"
	t "github.com/JonHarder/oauth/internal/types"
)

// tokenHandler handles the /token request by exchanging the access code for an access token.
func TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		grant, err := grants.ParseTokenRequest(req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Bad token exchange request: %v", err)
			return
		}

		var app t.Application
		if err := db.DB.First(&app, "client_id = ?", grant.GetClientId()).Error; err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "no application found with given client_id")
			return
		}
		log.Printf("APPLICATION: %v", app)

		accessToken, err := grant.CreateResponse(&app)
		if err != nil {
			log.Printf("ERROR: creating token response: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, err.Error())
			return
		}
		log.Printf("ACCESS_TOKEN: %v", accessToken)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		json.NewEncoder(w).Encode(accessToken)
	}
}
