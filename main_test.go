package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestSignupHandler(t *testing.T) {
	router := chi.NewRouter()
	router.Post("/signup", SignupHandler)

	user := User{
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
	router := chi.NewRouter()
	router.Post("/signup", SignupHandler)
	router.Post("/login", LoginHandler)

	// Signup the user first
	user := User{
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
	router := chi.NewRouter()
	router.Use(AuthMiddleware)
	router.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a protected route"))
	})

	// Generate a valid token
	tokenString, err := generateToken("testuser", jwtKey, 15*time.Minute)
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "This is a protected route", rr.Body.String())
}
