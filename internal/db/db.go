package db

import (
	"fmt"
	"log"

	t "github.com/JonHarder/oauth/internal/types"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

type Config struct {
	Name     string
	Host     string
	Username string
	Password string
	Port     int
}

func FindLoginRequestByCode(code t.Code) (*t.LoginRequest, error) {
	var loginReq t.LoginRequest
	if err := DB.Preload("Scopes").Preload("User").First(&loginReq, "code = ?", string(code)).Error; err != nil {
		return nil, err
	}
	return &loginReq, nil
}

func InitDB(config Config) {
	var port int
	if config.Port == 0 {
		port = 5432
	} else {
		port = config.Port
	}
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		config.Host,
		config.Username,
		config.Password,
		config.Name,
		port,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Error connecting to the database: %s", err.Error())
	}
	db.AutoMigrate(
		&t.Scope{},
		&t.TokenResponse{},
		&t.Application{},
		&t.AuthorizeRequest{},
		&t.User{},
		&t.RefreshRecord{},
		&t.Session{},
		&t.LoginRequest{},
	)

	DB = db
}
