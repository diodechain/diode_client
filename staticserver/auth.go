// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package staticserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Username string
	Password string
}

// BasicAuthMiddleware wraps an HTTP handler with HTTP Basic Authentication
func BasicAuthMiddleware(handler http.Handler, auth AuthConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract credentials from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			requestAuth(w)
			return
		}

		// Parse Basic Auth header
		const prefix = "Basic "
		if !strings.HasPrefix(authHeader, prefix) {
			requestAuth(w)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
		if err != nil {
			requestAuth(w)
			return
		}

		credentials := string(decoded)
		colonIndex := strings.Index(credentials, ":")
		if colonIndex == -1 {
			requestAuth(w)
			return
		}

		username := credentials[:colonIndex]
		password := credentials[colonIndex+1:]

		// Verify credentials using constant-time comparison to prevent timing attacks
		if !checkCredentials(username, password, auth.Username, auth.Password) {
			requestAuth(w)
			return
		}

		// Authentication successful, forward to handler
		handler.ServeHTTP(w, r)
	})
}

// checkCredentials performs constant-time comparison of credentials
func checkCredentials(username, password, expectedUsername, expectedPassword string) bool {
	// Hash the inputs to ensure constant-time comparison
	usernameHash := sha256.Sum256([]byte(username))
	expectedUsernameHash := sha256.Sum256([]byte(expectedUsername))
	passwordHash := sha256.Sum256([]byte(password))
	expectedPasswordHash := sha256.Sum256([]byte(expectedPassword))

	usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
	passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

	return usernameMatch && passwordMatch
}

// requestAuth sends a 401 Unauthorized response requesting authentication
func requestAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Diode Protected Site"`)
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintln(w, "401 Unauthorized - Authentication Required")
}
