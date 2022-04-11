package handlers

import (
	"fmt"
	"net/http"
	"strings"

	t "github.com/JonHarder/oauth/internal/types"
)

// ScopeTest checks the users access by checking if their access token was associated with the requested scope.
func ScopeTest(w http.ResponseWriter, req *http.Request, session t.Session) {
	query := req.URL.Query()
	resource := query.Get("resource")
	scopes := strings.Split(session.TokenResponse.Scope, " ")
	for _, scope := range scopes {
		if scope == resource {
			fmt.Fprintf(w, "User: %s has access to resource: %s", session.User.GivenName, resource)
			return
		}
	}
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "User: %s does NOT have access to resource: %s", session.User.GivenName, resource)
}
