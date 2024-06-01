package main

import (
	"bytes"
	"encoding/json"
	"example.com/m/types"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Post("/signup", SignupHandler)
	r.Post("/login", LoginHandler)
	r.Post("/refresh", RefreshHandler)
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("This is a protected route"))
		})
	})

	return r
}

func TestSignupHandler(t *testing.T) {
	router := setupRouter()

	user := types.User{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestLoginHandler(t *testing.T) {
	router := setupRouter()

	// Signup the user first
	user := types.User{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Now login with the same user
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]string
	json.NewDecoder(rr.Body).Decode(&response)

	assert.NotEmpty(t, response["access_token"])
	assert.NotEmpty(t, response["refresh_token"])
}

func TestProtectedRoute(t *testing.T) {
	router := setupRouter()

	// Generate a valid token
	tokenString, err := generateTestToken("testuser", jwtKey, 15*time.Minute)
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "This is a protected route", rr.Body.String())
}

func TestProtectedRouteInvalidToken(t *testing.T) {
	router := setupRouter()

	// Generate an invalid token
	invalidToken := "invalidtoken"

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "Forbidden\n", rr.Body.String())
}

func TestRefreshHandler(t *testing.T) {
	router := setupRouter()

	// Signup the user first
	user := types.User{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Now login with the same user
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var loginResponse map[string]string
	json.NewDecoder(rr.Body).Decode(&loginResponse)
	refreshToken := loginResponse["refresh_token"]

	// Refresh the access token
	refreshRequest := map[string]string{"refresh_token": refreshToken}
	refreshBody, _ := json.Marshal(refreshRequest)
	req, _ = http.NewRequest("POST", "/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var refreshResponse map[string]string
	json.NewDecoder(rr.Body).Decode(&refreshResponse)

	assert.NotEmpty(t, refreshResponse["access_token"])
}

// generateTestToken is used to generate a test JWT token for testing purposes
func generateTestToken(username string, key []byte, expiration time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiration)
	claims := &types.Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}
