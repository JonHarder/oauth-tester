package handlers

import (
	"fmt"

	t "github.com/JonHarder/oauth/internal/types"
	"github.com/gofiber/fiber/v2"
)

type userInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	FamilyName        string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	Email             string `json:"email"`
}

func UserInfoHandler(c *fiber.Ctx) error {
	session := c.Locals("session").(*t.Session)
	user := userInfo{
		Subject:           fmt.Sprint(session.User.ID),
		Name:              session.User.GivenName + " " + session.User.FamilyName,
		FamilyName:        session.User.FamilyName,
		PreferredUsername: string(session.User.GivenName[0]) + "." + session.User.FamilyName,
		GivenName:         session.User.GivenName,
		Email:             string(session.User.Email),
	}
	return c.JSON(user)
}
