package middleware

import (
	"html/template"
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
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			html.Execute(w, err.Error())
			return
		}

		session, ok := db.Sessions[token]
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			html.Execute(w, "No session found with bearer token")
			return
		}
		if session.Expired() {
			delete(db.Sessions, token)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			html.Execute(w, "Session expired")
			return
		}

		// otherwise we're good to go
		secureHandler(w, req, session)
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
