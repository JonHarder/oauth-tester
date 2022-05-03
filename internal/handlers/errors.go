package handlers

import (
	"log"
	"net/url"

	v "github.com/JonHarder/oauth/internal/validation"
	"github.com/gofiber/fiber/v2"
)

// handleBadRequest generates an error response to the callback.
// Redirects back to redirect_uri with error query parameter set
func HandleBadRequest(c *fiber.Ctx, redirect string, err v.ValidationError) error {
	parameters := url.Values{}
	parameters.Set("error", err.ErrorCode)
	parameters.Set("error_description", err.ErrorDescription)
	u := redirect + "?" + parameters.Encode()
	log.Printf("Redirecting to %s", u)
	return c.Redirect(u, 301)
}
