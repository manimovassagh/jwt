package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var jwtKey = []byte("my_secret_key")
var refreshKey = []byte("my_refresh_secret_key")

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

// In-memory user store
var userStore = struct {
	sync.RWMutex
	users map[string]string
}{users: make(map[string]string)}

// In-memory refresh token store
var refreshTokens = struct {
	sync.RWMutex
	tokens map[string]string
}{tokens: make(map[string]string)}

// AuthMiddleware validates the JWT
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")

		// Ensure the token string has the "Bearer " prefix
		if !strings.HasPrefix(tokenString, "Bearer ") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SignupHandler handles user registration
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userStore.Lock()
	defer userStore.Unlock()

	if _, exists := userStore.users[user.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	userStore.users[user.Username] = user.Password
	w.WriteHeader(http.StatusCreated)
}

// LoginHandler handles user login and returns access and refresh tokens
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userStore.RLock()
	defer userStore.RUnlock()

	storedPassword, exists := userStore.users[user.Username]
	if !exists || storedPassword != user.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateToken(user.Username, jwtKey, 15*time.Minute)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateToken(user.Username, refreshKey, 24*time.Hour)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	refreshTokens.Lock()
	refreshTokens.tokens[refreshToken] = user.Username
	refreshTokens.Unlock()

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	json.NewEncoder(w).Encode(response)
}

// RefreshHandler handles refreshing the access token
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var request map[string]string
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	refreshToken := request["refresh_token"]
	if refreshToken == "" {
		http.Error(w, "Refresh token required", http.StatusBadRequest)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	refreshTokens.RLock()
	username, exists := refreshTokens.tokens[refreshToken]
	refreshTokens.RUnlock()

	if !exists {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateToken(username, jwtKey, 15*time.Minute)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token": accessToken,
	}
	json.NewEncoder(w).Encode(response)
}

// generateToken generates a JWT token
func generateToken(username string, key []byte, expiration time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiration)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/signup", SignupHandler)
	r.Post("/login", LoginHandler)
	r.Post("/refresh", RefreshHandler)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a public route"))
	})

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("This is a protected route"))
		})
	})

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", r)
}
