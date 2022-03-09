package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// handleBadRequest generates an error response to the callback.
// Redirects back to redirect_uri with error query parameter set
func HandleBadRequest(w http.ResponseWriter, req *http.Request, redirect string, format string, vars ...interface{}) {
	parameters := url.Values{}
	parameters.Set("error", fmt.Sprintf(format, vars...))
	u := redirect + "?" + parameters.Encode()
	log.Printf("Redirecting to %s", u)
	http.Redirect(w, req, u, 301)
}
