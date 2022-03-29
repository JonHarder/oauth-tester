package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/JonHarder/oauth/internal/config"
	"github.com/JonHarder/oauth/internal/handlers"
	t "github.com/JonHarder/oauth/internal/types"
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
	for _, app := range config.Apps {
		app := app
		t.Applications[app.ClientId] = &app
		log.Printf("Applications configured:")
		log.Printf(" - Name: '%s': Client ID: '%s'", app.Name, app.ClientId)
	}
	for _, u := range config.Users {
		u := u
		t.Users[u.Email] = &u
	}
	log.Printf("======== END SETTINGS =========")

	// Routes
	http.HandleFunc("/authorize", handlers.AuthorizationHandler(*config))
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/token", handlers.TokenHandler)

	http.HandleFunc("/userinfo", handlers.UserInfoHandler)
	http.HandleFunc(
		"/.wellknown/openid-configuration",
		handlers.OpenIDConfigHandler,
	)
	// End Routes

	log.Printf("Listening on http://localhost:%d", options.port)
	log.Printf("Open ID Configuration endpoint: http://localhost:%d/.wellknown/openid-configuration", options.port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", options.port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
