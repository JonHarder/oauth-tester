package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/handlers"
	"github.com/JonHarder/oauth/internal/handlers/admin"
	"github.com/JonHarder/oauth/internal/middleware"
	"github.com/JonHarder/oauth/internal/util"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Options struct {
	configPath string
}

func indexHandler(c *fiber.Ctx) error {
	return c.SendFile(util.BinPath("public", "index.html"))
}

// main is the entry point to the oauth-server.
func main() {
	log.Printf("Initializing DB")
	db.InitDB(db.Config{
		Name:     os.Getenv("DB_DB"),
		Host:     os.Getenv("DB_HOST"),
		Username: os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
	})
	log.Printf("Finished Initializing DB")

	engine := html.New("./public", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Routes
	/// Public routes
	app.Get("/", indexHandler)
	app.Get("/authorize", handlers.AuthorizationHandler)
	app.Post("/login", handlers.LoginHandler)
	app.Post("/token", handlers.TokenHandler)
	// app.Get("/.wellknown/openid-configuration", handlers.OpenIDConfigHandler)

	// /// static assets
	app.Static("/css", "./public/css")

	// /// Secure routes
	app.Get("/userinfo", middleware.SecureAccessMiddleware, handlers.UserInfoHandler)
	app.Get("/scopetest", middleware.SecureAccessMiddleware, handlers.ScopeTest)

	// // Administrative routes
	adminApi := app.Group("/admin")
	adminApi.Get("/", admin.AdminIndex)
	adminApi.Get("/users", admin.AdminGetUsers)
	adminApi.Get("/users/:id", admin.AdminGetUser)
	adminApi.Get("/applications", admin.AdminGetApplications)
	adminApi.Post("/applications", admin.AdminCreateApplication)
	// End Routes

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}
	log.Printf("Listening on http://localhost:%s", port)
	log.Fatal(app.Listen(fmt.Sprintf(":%s", port)))
}
