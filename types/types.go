package types

import "github.com/dgrijalva/jwt-go"

// User represents a user in the system
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims represents the JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
