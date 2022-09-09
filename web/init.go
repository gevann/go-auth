package web

import (
	"github.com/gevann/go-auth/jwt"
)

func init() {
	jwt.ConfigureDatabase("jwt-service.db")
}
