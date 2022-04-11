package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/handlers"
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
	http.ServeFile(w, req, "./static/index.html")
}

// main is the entry point to the oauth-server.
func main() {
	html := util.BinPath("static", "login.html")
	if _, err := os.Stat(html); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("ERROR: html file 'login.html' not found.")
	}

	log.Printf("Endpoints:")
	log.Printf("   /authorize\t\t\t\tfor the oauth authorization request")
	log.Printf("   /token\t\t\t\tfor the oauth token exchange")
	log.Printf("   /userinfo\t\t\t\tfor additional information about users")
	log.Printf("   /scopetest\t\t\t\tfor checking user's access to a particular resource")
	log.Printf("   /.wellknown/openid-configuration\tfor openid metadata")

	db.InitDB(db.Config{
		Name:     os.Getenv("DB_DB"),
		Host:     os.Getenv("DB_HOST"),
		Username: os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
	})

	// Routes
	/// Public routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/authorize", handlers.AuthorizationHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc("/.wellknown/openid-configuration", handlers.OpenIDConfigHandler)

	/// Secure routes
	http.HandleFunc("/userinfo", middleware.SecureAccessMiddleware(handlers.UserInfoHandler))
	http.HandleFunc("/scopetest", middleware.SecureAccessMiddleware(handlers.ScopeTest))
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
