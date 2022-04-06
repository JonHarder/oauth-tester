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
	db.AutoMigrate(&t.Scope{})
	db.AutoMigrate(&t.TokenResponse{})
	db.AutoMigrate(&t.Application{})
	db.AutoMigrate(&t.AuthorizeRequest{})
	db.AutoMigrate(&t.User{})
	db.AutoMigrate(&t.RefreshRecord{})
	db.AutoMigrate(&t.Session{})
	db.AutoMigrate(&t.LoginRequest{})

	DB = db
}
