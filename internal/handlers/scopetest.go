package handlers

import (
	"fmt"
	"strings"

	t "github.com/JonHarder/oauth/internal/types"
	"github.com/gofiber/fiber/v2"
)

// ScopeTest checks the users access by checking if their access token was associated with the requested scope.
func ScopeTest(c *fiber.Ctx) error {
	session := c.Locals("session").(*t.Session)
	resource := c.Query("resource")
	scopes := strings.Split(session.TokenResponse.Scope, " ")
	for _, scope := range scopes {
		if scope == resource {
			return c.SendString(fmt.Sprintf("User: %s has access to resource: %s", session.User.GivenName, resource))
		}
	}
	return c.Status(fiber.StatusForbidden).
		SendString(fmt.Sprintf("User: %s does NOT have access to resource: %s", session.User.GivenName, resource))
}
