package handlers

import (
	"fmt"
	"log"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth/grants"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/gofiber/fiber/v2"
)

// tokenHandler handles the /token request by exchanging the access code for an access token.
func TokenHandler(c *fiber.Ctx) error {
	grant, err := grants.ParseTokenRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(fmt.Sprintf("Bad token exchange request: %v", err))
	}

	var app t.Application
	if err := db.DB.First(&app, "client_id = ?", grant.GetClientId()).Error; err != nil {
		return c.Status(fiber.StatusNotFound).SendString("no application found with given client_id")
	}
	log.Printf("APPLICATION: %v", app)

	accessToken, err := grant.CreateResponse(&app)
	if err != nil {
		log.Printf("ERROR: creating token response: %s", err.Error())
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	log.Printf("ACCESS_TOKEN: %v", accessToken)
	return c.JSON(accessToken)
}
