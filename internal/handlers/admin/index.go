package admin

import (
	"github.com/gofiber/fiber/v2"
)

var indexHtml string = `
<!DOCTYPE html>
<html>
  <body>
    <ul>
      <li><a href='/admin/users'>Users</a></li>
      <li><a href='/admin/applications'>Applications</a></li>
    </ul>
  </body>
</html>
`

func AdminIndex(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/html")
	return c.SendString(indexHtml)
}
