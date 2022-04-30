package middleware

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth"
	t "github.com/JonHarder/oauth/internal/types"
)

var html *template.Template

type SecureHandler func(w http.ResponseWriter, req *http.Request, session t.Session)

// SecureAccessMiddleware ensures an endpoint is accessible by users with valid bearer tokens only.
func SecureAccessMiddleware(secureHandler SecureHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		token, err := oauth.GetBearerToken(req.Header)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			html.Execute(w, err.Error())
			return
		}

		session, err := db.FindSessionByAccessToken(token)
		if err != nil {
			log.Printf("error finding session: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, err.Error())
			return
		}
		if session == nil {
			log.Printf("Session not found")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Session not found")
			return
		}
		log.Printf("session: time granted: %v, token_response_id: %d", session.TimeGranted, session.TokenResponseID)
		if session.Expired() {
			log.Printf("Session expired")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			html.Execute(w, "Session expired")
			return
		}

		// otherwise we're good to go
		secureHandler(w, req, *session)
	}
}

func init() {
	html = template.Must(template.New("denied").Parse(`
<html>
  <head>
    <title>Access Denied!</title>
  </head>
  <body>
    <h1>Forbidden</h1>
    <h2>{{.}}.</h2>
  </body>
</html>
`))
}
