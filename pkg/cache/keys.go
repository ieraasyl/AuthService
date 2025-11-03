// Package cache provides standardized cache key generation functions.
// Using consistent key naming helps avoid collisions and makes cache
// management easier. All keys follow the pattern: "prefix:identifier".
package cache

import (
	"fmt"

	"github.com/google/uuid"
)

// Key prefixes for different cache types.
// These constants ensure consistent key naming across the application.
const (
	UserPrefix        = "user:"
	SessionPrefix     = "session:"
	TokenPrefix       = "token:"
	GeoLocationPrefix = "geo:"
)

// UserKey generates a cache key for user data by ID.
// Use this for caching full user objects.
//
// Example: "user:123e4567-e89b-12d3-a456-426614174000"
func UserKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s%s", UserPrefix, userID.String())
}

// UserByEmailKey generates a cache key for user lookup by email.
// Use this for email-based user queries.
//
// Example: "user:email:user@example.com"
func UserByEmailKey(email string) string {
	return fmt.Sprintf("%semail:%s", UserPrefix, email)
}

// UserByGoogleIDKey generates a cache key for user lookup by Google ID.
// Use this for OAuth-based user queries.
//
// Example: "user:google:1234567890"
func UserByGoogleIDKey(googleID string) string {
	return fmt.Sprintf("%sgoogle:%s", UserPrefix, googleID)
}

// SessionKey generates a cache key for session data.
// Sessions are scoped per user and identified by a unique session ID.
//
// Example: "session:123e4567-e89b-12d3-a456-426614174000:abc123"
func SessionKey(userID uuid.UUID, sessionID string) string {
	return fmt.Sprintf("%s%s:%s", SessionPrefix, userID.String(), sessionID)
}

// SessionListKey generates a cache key for a user's session list.
// Use this to cache the list of all active sessions for a user.
//
// Example: "session:list:123e4567-e89b-12d3-a456-426614174000"
func SessionListKey(userID uuid.UUID) string {
	return fmt.Sprintf("%slist:%s", SessionPrefix, userID.String())
}

// TokenKey generates a cache key for token data (blacklist, metadata, etc.).
// Use this for JWT blacklisting or token metadata caching.
//
// Example: "token:eyJhbGciOiJIUzI1NiIs..."
func TokenKey(token string) string {
	return fmt.Sprintf("%s%s", TokenPrefix, token)
}

// UserPattern returns a glob pattern matching all user cache keys for a specific user.
// Use with DeletePattern to invalidate all user-related cache.
//
// Example: "user:123e4567-e89b-12d3-a456-426614174000*"
func UserPattern(userID uuid.UUID) string {
	return fmt.Sprintf("%s%s*", UserPrefix, userID.String())
}

// UserAllPattern returns a glob pattern matching all user-related cache keys.
// Use this to clear all user caches (use with caution in production).
//
// Example: "user:*"
func UserAllPattern() string {
	return fmt.Sprintf("%s*", UserPrefix)
}

// GeoLocationKey generates a cache key for geolocation data by IP address.
// Geolocation lookups are expensive, so caching with long TTL is recommended.
//
// Example: "geo:192.168.1.1"
func GeoLocationKey(ipAddress string) string {
	return fmt.Sprintf("%s%s", GeoLocationPrefix, ipAddress)
}
