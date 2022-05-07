package admin

import (
	"net/url"

	"github.com/JonHarder/oauth/internal/db"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	"github.com/gofiber/fiber/v2"
)

type appCreateRequest struct {
	Name         string `json:"name" form:"name"`
	ClientId     string `json:"client_id" form:"client_id"`
	ClientSecret string
	Callback     string `json:"callback" form:"callback"`
}

func AdminGetApplications(c *fiber.Ctx) error {
	// display new application form
	c.Set("Content-Type", "text/html")
	var apps []t.Application
	if err := db.DB.Find(&apps).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString(err.Error())
	}
	return c.Render("applications", apps)
}

func AdminCreateApplication(c *fiber.Ctx) error {
	appRequest := appCreateRequest{
		ClientSecret: util.RandomString(32),
	}
	if err := c.BodyParser(&appRequest); err != nil {
		return c.
			Status(fiber.StatusInternalServerError).
			SendString(err.Error())
	}
	callback, err := url.QueryUnescape(appRequest.Callback)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	name, err := url.QueryUnescape(appRequest.Name)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	app := t.Application{
		ClientId:     appRequest.ClientId,
		ClientSecret: appRequest.ClientSecret,
		Callback:     callback,
		Name:         name,
	}
	if err := db.DB.Create(&app).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	return c.JSON(app)
}
