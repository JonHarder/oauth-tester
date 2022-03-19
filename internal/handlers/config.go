package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/JonHarder/oauth/internal/constants"
)

type OpenIdConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

var Configuration = OpenIdConfiguration{
	Issuer:                constants.ISSUER,
	AuthorizationEndpoint: constants.ISSUER + "/authorize",
	TokenEndpoint:         constants.ISSUER + "/token",
}

func ConfigHandler(w http.ResponseWriter, req *http.Request) {
	data, err := json.Marshal(Configuration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}
