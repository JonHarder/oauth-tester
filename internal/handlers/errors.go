package handlers

import (
	"log"
	"net/http"
	"net/url"

	v "github.com/JonHarder/oauth/internal/validation"
)

// handleBadRequest generates an error response to the callback.
// Redirects back to redirect_uri with error query parameter set
func HandleBadRequest(w http.ResponseWriter, req *http.Request, redirect string, err v.ValidationError) {
	parameters := url.Values{}
	parameters.Set("error", err.ErrorCode)
	parameters.Set("error_description", err.ErrorDescription)
	u := redirect + "?" + parameters.Encode()
	log.Printf("Redirecting to %s", u)
	http.Redirect(w, req, u, 301)
}
