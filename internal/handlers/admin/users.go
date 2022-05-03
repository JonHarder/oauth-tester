package admin

import (
	"log"

	"github.com/JonHarder/oauth/internal/db"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/gofiber/fiber/v2"
)

func AdminGetUsers(c *fiber.Ctx) error {
	var users []t.User
	if err := db.DB.Find(&users).Error; err != nil {
		log.Printf("ERROR: %s", err.Error())
		return c.Status(fiber.StatusInternalServerError).
			SendString(err.Error())
	}
	return c.Render("users", users)
}

func AdminGetUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user t.User
	if err := db.DB.Find(&user, "id = ?", id).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	return c.Render("user", user)
}
