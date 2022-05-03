package handlers

import (
	"github.com/JonHarder/oauth/internal/constants"
	"github.com/gofiber/fiber/v2"
)

type OpenIdConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"user_info_endpoint"`
}

var Configuration = OpenIdConfiguration{
	Issuer:                constants.ISSUER,
	AuthorizationEndpoint: "http://127.0.0.1:8001/authorize",
	TokenEndpoint:         "http://127.0.0.1:8001/token",
	UserInfoEndpoint:      "http://127.0.0.1:8001/userinfo",
}

func OpenIDConfigHandler(c *fiber.Ctx) error {
	return c.JSON(Configuration)
}
