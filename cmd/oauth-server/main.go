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

	"github.com/JonHarder/oauth/internal/handlers"
	t "github.com/JonHarder/oauth/internal/types"
)

type Config struct {
	Apps  []t.Application `json:"applications"`
	Users []t.User        `json:"users"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// readConfig takes a path to a config.json file and parses it as a Config object.
func readConfig(path string) (*Config, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(dat, &config); err != nil {
		return nil, err
	}
	if len(config.Apps) == 0 {
		return nil, fmt.Errorf("Invalid config.json: missing or empty \"appcliatons\"")
	}
	if len(config.Users) == 0 {
		return nil, fmt.Errorf("Invalid config.json: missing or empty \"users\"")
	}
	for i, app := range config.Apps {
		if app.Callback == "" || app.ClientId == "" || app.ClientSecret == "" || app.Name == "" {
			return nil, fmt.Errorf(
				"Invalid config.json: applications[%d] is missing one of: clientId, clientSecret, callback, name",
				i,
			)
		}
	}
	for i, user := range config.Users {
		if user.Email == "" || user.Fname == "" || user.Lname == "" || user.Password == "" {
			return nil, fmt.Errorf(
				"Invalid config.json: users[%d] is missing one of: email, password, fname, lname",
				i,
			)
		}
	}
	return &config, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// main is the entry point to the oauth-server.
func main() {
	var port int
	var configPath string
	flag.IntVar(&port, "port", 8001, "Port to run server on")
	flag.StringVar(&configPath, "config", "config.json", "Path to the configuration file containing applications and users")
	flag.Parse()

	if _, err := os.Stat("login.html"); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("ERROR: html file 'login.html' not found.")
	}

	config, err := readConfig(configPath)
	if err != nil {
		log.Fatalf("Error reading configuration file: %v", err)
	}
	for _, app := range config.Apps {
		app := app
		t.Applications[app.ClientId] = &app
	}
	for _, u := range config.Users {
		u := u
		t.Users[u.Email] = &u
	}

	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/authorize", handlers.AuthorizationHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc(
		"/.wellknown/openid-configuration",
		handlers.ConfigHandler,
	)

	log.Printf("Listening on http://localhost:%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
