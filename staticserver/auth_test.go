// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package staticserver

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthMiddleware(t *testing.T) {
	// Create a simple test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	})

	// Create auth config
	auth := AuthConfig{
		Username: "testuser",
		Password: "testpass",
	}

	// Wrap handler with authentication
	authHandler := BasicAuthMiddleware(testHandler, auth)

	// Test 1: No authentication
	t.Run("No Auth Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}

		if rr.Header().Get("WWW-Authenticate") == "" {
			t.Error("Expected WWW-Authenticate header")
		}
	})

	// Test 2: Correct credentials
	t.Run("Correct Credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		credentials := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
		req.Header.Set("Authorization", "Basic "+credentials)
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		if rr.Body.String() != "Success" {
			t.Errorf("Expected 'Success', got '%s'", rr.Body.String())
		}
	})

	// Test 3: Incorrect username
	t.Run("Incorrect Username", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		credentials := base64.StdEncoding.EncodeToString([]byte("wronguser:testpass"))
		req.Header.Set("Authorization", "Basic "+credentials)
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	// Test 4: Incorrect password
	t.Run("Incorrect Password", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		credentials := base64.StdEncoding.EncodeToString([]byte("testuser:wrongpass"))
		req.Header.Set("Authorization", "Basic "+credentials)
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	// Test 5: Malformed auth header
	t.Run("Malformed Auth Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Basic invalid")
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	// Test 6: Non-Basic auth
	t.Run("Non-Basic Auth Scheme", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer sometoken")
		rr := httptest.NewRecorder()

		authHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})
}

func TestCheckCredentials(t *testing.T) {
	tests := []struct {
		name              string
		username          string
		password          string
		expectedUsername  string
		expectedPassword  string
		expectedResult    bool
	}{
		{
			name:             "Correct credentials",
			username:         "user1",
			password:         "pass1",
			expectedUsername: "user1",
			expectedPassword: "pass1",
			expectedResult:   true,
		},
		{
			name:             "Wrong username",
			username:         "user1",
			password:         "pass1",
			expectedUsername: "user2",
			expectedPassword: "pass1",
			expectedResult:   false,
		},
		{
			name:             "Wrong password",
			username:         "user1",
			password:         "pass1",
			expectedUsername: "user1",
			expectedPassword: "pass2",
			expectedResult:   false,
		},
		{
			name:             "Both wrong",
			username:         "user1",
			password:         "pass1",
			expectedUsername: "user2",
			expectedPassword: "pass2",
			expectedResult:   false,
		},
		{
			name:             "Empty credentials",
			username:         "",
			password:         "",
			expectedUsername: "",
			expectedPassword: "",
			expectedResult:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkCredentials(tt.username, tt.password, tt.expectedUsername, tt.expectedPassword)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}
