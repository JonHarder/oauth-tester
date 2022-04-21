package admin

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/JonHarder/oauth/internal/db"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
)

func AdminUsers(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		var users []t.User
		if err := db.DB.Find(&users).Error; err != nil {
			log.Printf("ERROR: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, err.Error())
			return
		}
		userTable.Execute(w, users)
		return
	}
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Method not allowed")
	}
}

func AdminUser(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/admin/users/")
	var user t.User
	if err := db.DB.Find(&user, "id = ?", id).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
		return
	}
	fmt.Fprintf(w, "%s %s", user.GivenName, user.FamilyName)
}

var userTable *template.Template

func init() {
	userTable = template.Must(template.New("users.html").ParseFiles(util.BinPath("public", "users.html")))
}
