package config

import (
	"encoding/json"
	"log"
	"os"

	t "github.com/JonHarder/oauth/internal/types"
)

type PkceSetting struct {
	Enabled        bool     `json:"enabled"`
	AllowedMethods []string `json:"allowed_methods"`
}

type Settings struct {
	Pkce PkceSetting `json:"pkce"`
}

type Config struct {
	Apps     []t.Application `json:"applications"`
	Users    []t.User        `json:"users"`
	Settings Settings        `json:"settings"`
}

// readConfig takes a path to a config.json file and parses it as a Config object.
// panics if encountering an error parsing the config file
func ReadConfig(path string) *Config {
	dat, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("%v", err)
	}
	var config Config
	if err := json.Unmarshal(dat, &config); err != nil {
		log.Fatalf("%v", err)
	}
	if len(config.Apps) == 0 {
		log.Fatalf("Invalid config.json: missing or empty \"applications\"")
	}
	if len(config.Users) == 0 {
		log.Fatalf("Invalid config.json: missing or empty \"users\"")
	}
	for i, app := range config.Apps {
		if app.Callback == "" || app.ClientId == "" || app.ClientSecret == "" || app.Name == "" {
			log.Fatalf(
				"Invalid config.json: applications[%d] is missing one of: clientId, clientSecret, callback, name",
				i,
			)
		}
	}
	for i, user := range config.Users {
		if user.Email == "" || user.Fname == "" || user.Lname == "" || user.Password == "" {
			log.Fatalf(
				"Invalid config.json: users[%d] is missing one of: email, password, fname, lname",
				i,
			)
		}
	}
	return &config
}
