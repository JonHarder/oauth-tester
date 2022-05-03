package middleware

import (
	"html/template"
	"log"

	"github.com/JonHarder/oauth/internal/db"
	"github.com/JonHarder/oauth/internal/oauth"
	"github.com/gofiber/fiber/v2"
)

var html *template.Template

// SecureAccessMiddleware ensures an endpoint is accessible by users with valid bearer tokens only.
func SecureAccessMiddleware(c *fiber.Ctx) error {
	token, err := oauth.GetBearerToken(c)
	if err != nil {
		log.Print(err)
		return c.Status(fiber.StatusForbidden).SendString(err.Error())
	}

	session, err := db.FindSessionByAccessToken(token)
	if err != nil {
		log.Printf("error finding session: %v", err)
		return c.Status(fiber.StatusInternalServerError).
			SendString(err.Error())
	}
	if session == nil {
		log.Printf("Session not found")
		return c.Status(fiber.StatusNotFound).SendString("Session not found")
	}
	log.Printf("session: time granted: %v, token_response_id: %d", session.TimeGranted, session.TokenResponseID)
	if session.Expired() {
		log.Printf("Session expired")
		return c.Status(fiber.StatusForbidden).
			SendString("Session expired")
	}
	c.Locals("session", session)

	return c.Next()
}

func init() {
	html = template.Must(template.New("denied").Parse(`
<html>
  <head>
    <title>Access Denied!</title>
  </head>
  <body>
    <h1>Forbidden</h1>
    <h2>{{.}}.</h2>
  </body>
</html>
`))
}
