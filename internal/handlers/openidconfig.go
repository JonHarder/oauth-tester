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
	UserInfoEndpoint      string `json:"user_info_endpoint"`
}

var Configuration = OpenIdConfiguration{
	Issuer:                constants.ISSUER,
	AuthorizationEndpoint: "http://127.0.0.1:8001/authorize",
	TokenEndpoint:         "http://127.0.0.1:8001/token",
	UserInfoEndpoint:      "http://127.0.0.1:8001/userinfo",
}

func OpenIDConfigHandler(w http.ResponseWriter, req *http.Request) {
	data, err := json.MarshalIndent(Configuration, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}
