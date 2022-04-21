package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/handlers"
	"github.com/JonHarder/oauth/internal/handlers/admin"
	"github.com/JonHarder/oauth/internal/middleware"
	"github.com/JonHarder/oauth/internal/util"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Options struct {
	configPath string
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html")
		t := template.Must(template.New("404.html").Parse(`
            <html>
              <head>
                <title>Not Found</title>
              </head>
              <body>
                <h1>404 Not Found</h1>
                <h2>Page {{.}} Not found</h2>
              </body>
            </html>
        `))
		t.Execute(w, req.URL.Path)
		return
	}
	http.ServeFile(w, req, "./public/index.html")
}

// main is the entry point to the oauth-server.
func main() {
	html := util.BinPath("public", "login.html")
	if _, err := os.Stat(html); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("ERROR: html file 'login.html' not found.")
	}

	log.Printf("Initializing DB")
	db.InitDB(db.Config{
		Name:     os.Getenv("DB_DB"),
		Host:     os.Getenv("DB_HOST"),
		Username: os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
	})
	log.Printf("Finished Initializing DB")

	// Routes
	/// Public routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/authorize", handlers.AuthorizationHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc("/.wellknown/openid-configuration", handlers.OpenIDConfigHandler)

	/// static assets
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./public/css"))))

	/// Secure routes
	http.HandleFunc("/userinfo", middleware.SecureAccessMiddleware(handlers.UserInfoHandler))
	http.HandleFunc("/scopetest", middleware.SecureAccessMiddleware(handlers.ScopeTest))

	// Administrative routes
	http.HandleFunc("/admin", admin.AdminIndex)
	http.HandleFunc("/admin/applications", admin.AdminApplications)
	http.HandleFunc("/admin/users", admin.AdminUsers)
	http.HandleFunc("/admin/users/", admin.AdminUser)
	// End Routes

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}
	log.Printf("Listening on http://localhost:%s", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
