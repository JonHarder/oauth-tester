package admin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/parameters"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
)

type appCreateRequest struct {
	Name         string `json:"name"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Callback     string `json:"callback"`
}

func parseAppCreateRequest(req *http.Request) (*appCreateRequest, error) {
	params, err := parameters.NewFromForm(req)
	log.Printf("%v", params)
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		return nil, err
	}
	if !params.Has("name") {
		return nil, fmt.Errorf("missing required field: name")
	}
	if !params.Has("client_id") {
		return nil, fmt.Errorf("missing required field: client_id")
	}
	if !params.Has("callback") {
		return nil, fmt.Errorf("missing required field: callback")
	}
	clientSecret := util.RandomString(32)
	return &appCreateRequest{
		Name:         params.Get("name", ""),
		ClientId:     params.Get("client_id", ""),
		ClientSecret: clientSecret,
		Callback:     params.Get("callback", ""),
	}, nil
}

func AdminApplications(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		// display new application form
		w.Header().Set("Content-Type", "text/html")
		var apps []t.Application
		if err := db.DB.Find(&apps).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, err.Error())
			return
		}
		applications.Execute(w, apps)
		return
	}
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Method not allowed.")
		return
	}

	appRequest, err := parseAppCreateRequest(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, err.Error())
		return
	}
	app := t.Application{
		ClientId:     appRequest.ClientId,
		ClientSecret: appRequest.ClientSecret,
		Callback:     appRequest.Callback,
		Name:         appRequest.Name,
	}
	if err := db.DB.Create(&app).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(app)
}

var applications *template.Template

func init() {
	applications = template.Must(
		template.
			New("applications.html").
			ParseFiles(util.BinPath("public", "applications.html")),
	)
}
