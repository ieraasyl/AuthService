// Package models defines the core domain models for the application.
// These models represent the data structures used throughout the system
// for users, sessions, and authentication state.
//
// All models include appropriate JSON and database struct tags for
// serialization and ORM mapping. Sensitive fields are marked with `json:"-"`
// to prevent accidental exposure in API responses.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user account in the system, authenticated via Google OAuth.
// Users are uniquely identified by their UUID and linked to their Google account
// via the GoogleID field.
//
// The LastLogin field is nullable to handle users who have never logged in or
// whose login history was cleared.
//
// JSON example:
//
//	{
//	  "id": "550e8400-e29b-41d4-a716-446655440000",
//	  "google_id": "1234567890",
//	  "email": "user@example.com",
//	  "name": "John Doe",
//	  "picture_url": "https://lh3.googleusercontent.com/...",
//	  "created_at": "2024-01-15T10:30:00Z",
//	  "updated_at": "2024-01-15T10:30:00Z",
//	  "last_login": "2024-01-20T14:45:00Z"
//	}
type User struct {
	ID         uuid.UUID  `json:"id" db:"id"`                           // Unique user identifier
	GoogleID   string     `json:"google_id" db:"google_id"`             // Google account ID (unique)
	Email      string     `json:"email" db:"email"`                     // User's email address from Google
	Name       string     `json:"name" db:"name"`                       // Display name from Google profile
	PictureURL string     `json:"picture_url" db:"picture_url"`         // Profile picture URL from Google
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`           // Account creation timestamp
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`           // Last profile update timestamp
	LastLogin  *time.Time `json:"last_login,omitempty" db:"last_login"` // Most recent login time (nullable)
}

// Session represents an active user session backed by Redis storage.
// Sessions are created after successful OAuth authentication and contain
// the refresh token needed to obtain new access tokens.
//
// The RefreshToken field is intentionally excluded from JSON serialization
// (via `json:"-"`) to prevent exposure in API responses or logs.
//
// Sessions are stored in Redis with automatic expiration based on the
// ExpiresAt timestamp. The DeviceInfo and IPAddress fields enable security
// features like session listing and suspicious activity detection.
//
// Example (internal representation):
//
//	Session{
//	  ID: "sess_abc123",
//	  UserID: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
//	  RefreshToken: "eyJhbGciOiJIUzI1NiIs...",
//	  DeviceInfo: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
//	  IPAddress: "192.168.1.100",
//	  CreatedAt: time.Now(),
//	  ExpiresAt: time.Now().Add(7*24*time.Hour),
//	}
type Session struct {
	ID           string    `json:"id"`          // Unique session identifier
	UserID       uuid.UUID `json:"user_id"`     // User this session belongs to
	RefreshToken string    `json:"-"`           // JWT refresh token (NEVER exposed in JSON)
	DeviceInfo   string    `json:"device_info"` // User-Agent string from authentication
	IPAddress    string    `json:"ip_address"`  // Client IP address (supports IPv4/IPv6)
	CreatedAt    time.Time `json:"created_at"`  // Session creation timestamp
	ExpiresAt    time.Time `json:"expires_at"`  // Session expiration timestamp (7 days default)
}

// SessionInfo is a sanitized version of Session for public API responses.
// It excludes sensitive fields like RefreshToken and UserID, making it safe
// to return in session listing endpoints.
//
// Use this type when returning active sessions to the authenticated user,
// allowing them to view and manage their sessions without exposing
// security-critical data.
//
// JSON example:
//
//	{
//	  "id": "sess_abc123",
//	  "device_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
//	  "ip_address": "192.168.1.100",
//	  "created_at": "2024-01-20T14:45:00Z",
//	  "expires_at": "2024-01-27T14:45:00Z"
//	}
type SessionInfo struct {
	ID         string    `json:"id"`          // Session identifier
	DeviceInfo string    `json:"device_info"` // Device/browser information
	IPAddress  string    `json:"ip_address"`  // Client IP address
	CreatedAt  time.Time `json:"created_at"`  // When session was created
	ExpiresAt  time.Time `json:"expires_at"`  // When session will expire
}
