package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/JonHarder/oauth/internal/config"
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
	port       int
	configPath string
}

func parseOptions() Options {
	options := Options{}
	flag.IntVar(&options.port, "port", 8001, "Port to run server on")
	flag.StringVar(&options.configPath, "config", "config.json", "Path to configuration file")
	flag.Parse()
	return options
}

func settingsHandler(c *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.Settings)
	}
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	html := `
<html>
  <head>
    <title>OAuth Server</title>
  </head>
  <body>
    <nav>
     <h3>Public</h3>
     <ul>
      <li><a href="/settings">Settings</a></li>
      <li><a href="/.wellknown/openid-configuration">Open ID Configuration</a></li>
     </ul>
    </nav>
  </body>
</html>
`
	fmt.Fprintf(w, html)
}

// main is the entry point to the oauth-server.
func main() {
	options := parseOptions()

	html := util.BinPath("static", "login.html")
	if _, err := os.Stat(html); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("ERROR: html file 'login.html' not found.")
	}

	config := config.ReadConfig(options.configPath)
	log.Printf("========= SETTINGS ==============")
	log.Printf("pkce required: %t", config.Settings.Pkce.Required)
	if config.Settings.Pkce.Required {
		log.Printf(" - Allowed challenge methods: %v\n", config.Settings.Pkce.AllowedMethods)
	}
	db.LoadFromConfig(*config)

	// Routes
	/// Public routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/authorize", handlers.AuthorizationHandler(*config))
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc("/.wellknown/openid-configuration", handlers.OpenIDConfigHandler)

	http.HandleFunc("/settings", settingsHandler(config))

	/// Secure routes
	http.HandleFunc("/userinfo", middleware.SecureAccessMiddleware(handlers.UserInfoHandler))
	http.HandleFunc("/scopetest", middleware.SecureAccessMiddleware(handlers.ScopeTest))
	// End Routes

	log.Printf("Endpoints:")
	log.Printf("   /authorize\t\t\t\tfor the oauth authorization request")
	log.Printf("   /token\t\t\t\tfor the oauth token exchange")
	log.Printf("   /userinfo\t\t\t\tfor additional information about users")
	log.Printf("   /scopetest\t\t\t\tfor checking user's access to a particular resource")
	log.Printf("   /.wellknown/openid-configuration\tfor openid metadata")
	log.Printf("======== END SETTINGS =========")
	log.Printf("Listening on http://localhost:%d", options.port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", options.port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
