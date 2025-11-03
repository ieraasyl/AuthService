// Package middleware provides HTTP middleware components for the API.
// Middleware functions wrap HTTP handlers to provide cross-cutting concerns
// like authentication, logging, metrics, and rate limiting.
//
// Middleware in this package:
//   - JWT authentication and authorization
//   - Structured request/response logging with correlation IDs
//   - Prometheus metrics collection
//   - Rate limiting per IP address
//
// All middleware is designed to be composable with Chi router.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/ieraasyl/AuthService/internal/services"
	"github.com/rs/zerolog/log"
)

// contextKey is a custom type for context keys to avoid collisions.
// Using a custom type prevents conflicts with other packages that might
// use string keys in the context.
type contextKey string

const (
	// UserIDKey is the context key for storing the authenticated user's ID.
	// Set by JWTAuth middleware after successful token validation.
	UserIDKey contextKey = "user_id"

	// UserEmailKey is the context key for storing the authenticated user's email.
	// Set by JWTAuth middleware after successful token validation.
	UserEmailKey contextKey = "email"
)

// JWTAuth creates middleware that validates JWT tokens and adds user info to context.
// This is the primary authentication middleware for protected endpoints.
//
// Token sources (checked in order):
//  1. Authorization header: "Bearer <token>"
//  2. Cookie: access_token=<token>
//
// On successful authentication:
//   - User ID and email are added to request context
//   - Request proceeds to next handler
//
// On authentication failure:
//   - Request is rejected with 401 Unauthorized
//   - Detailed error is logged
//
// The middleware performs:
//   - Token signature verification
//   - Expiration checking
//   - Blacklist verification (for revoked tokens)
//
// Usage:
//
//	// Protect specific routes
//	r.Group(func(r chi.Router) {
//	    r.Use(middleware.JWTAuth(jwtService))
//	    r.Get("/api/auth/me", authHandler.Me)
//	    r.Get("/api/auth/sessions", authHandler.ListSessions)
//	})
//
// Accessing user info in handlers:
//
//	func (h *Handler) ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
//	    userID, ok := middleware.GetUserID(r.Context())
//	    if !ok {
//	        // This shouldn't happen if middleware is working correctly
//	        http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	        return
//	    }
//	    // Use userID...
//	}
func JWTAuth(jwtService *services.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// Try to get token from cookie as fallback
				cookie, err := r.Cookie("access_token")
				if err != nil {
					log.Warn().Msg("Missing authorization token")
					http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
					return
				}
				authHeader = cookie.Value
			} else {
				// Remove "Bearer " prefix
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			}

			// Validate token
			claims, err := jwtService.ValidateToken(r.Context(), authHeader)
			if err != nil {
				log.Warn().Err(err).Msg("Invalid token")
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			// Add user info to context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, UserEmailKey, claims.Email)

			log.Debug().
				Str("user_id", claims.UserID).
				Str("email", claims.Email).
				Msg("User authenticated via JWT")

			// Call next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts the authenticated user's ID from the request context.
// Returns the user ID string and a boolean indicating whether it was found.
//
// This function should be called in handlers that use the JWTAuth middleware
// to access the authenticated user's identity.
//
// Returns:
//   - string: The user's UUID as a string
//   - bool: true if the user ID was found in context, false otherwise
//
// Example:
//
//	userID, ok := middleware.GetUserID(r.Context())
//	if !ok {
//	    http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	    return
//	}
//	uid, _ := uuid.Parse(userID)
//	user, err := db.GetUserByID(ctx, uid)
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

// GetUserEmail extracts the authenticated user's email from the request context.
// Returns the email string and a boolean indicating whether it was found.
//
// This function should be called in handlers that use the JWTAuth middleware
// to access the authenticated user's email address.
//
// Returns:
//   - string: The user's email address
//   - bool: true if the email was found in context, false otherwise
//
// Example:
//
//	email, ok := middleware.GetUserEmail(r.Context())
//	if ok {
//	    log.Info().Str("email", email).Msg("Request from authenticated user")
//	}
func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}
