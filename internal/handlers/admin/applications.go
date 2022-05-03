package admin

import (
	"fmt"

	"github.com/JonHarder/oauth/internal/db"
	t "github.com/JonHarder/oauth/internal/types"
	"github.com/JonHarder/oauth/internal/util"
	"github.com/gofiber/fiber/v2"
)

type appCreateRequest struct {
	Name         string `json:"name"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Callback     string `json:"callback"`
}

func parseAppCreateRequest(c *fiber.Ctx) (*appCreateRequest, error) {
	name := c.FormValue("name", "")
	if name == "" {
		return nil, fmt.Errorf("missing required field: name")
	}
	clientId := c.FormValue("client_id", "")
	if clientId == "" {
		return nil, fmt.Errorf("missing required field: client_id")
	}
	callback := c.FormValue("callback", "")
	if callback == "" {
		return nil, fmt.Errorf("missing required field: callback")
	}
	clientSecret := util.RandomString(32)
	return &appCreateRequest{
		Name:         name,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Callback:     callback,
	}, nil
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
	appRequest, err := parseAppCreateRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	app := t.Application{
		ClientId:     appRequest.ClientId,
		ClientSecret: appRequest.ClientSecret,
		Callback:     appRequest.Callback,
		Name:         appRequest.Name,
	}
	if err := db.DB.Create(&app).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	return c.JSON(app)
}
