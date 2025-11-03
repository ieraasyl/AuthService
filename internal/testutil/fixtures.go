// Package testutil provides common testing utilities, fixtures, and helpers
// for use across all test files in the AuthService project.
package testutil

import (
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/models"
)

// TestUser creates a test user with default values
func TestUser() *models.User {
	return &models.User{
		ID:         uuid.New(),
		GoogleID:   "test-google-id-123",
		Email:      "test@example.com",
		Name:       "Test User",
		PictureURL: "https://example.com/picture.jpg",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastLogin:  TimePtr(time.Now()),
	}
}

// TestUserWithEmail creates a test user with a specific email
func TestUserWithEmail(email string) *models.User {
	user := TestUser()
	user.Email = email
	return user
}

// TestUserWithGoogleID creates a test user with a specific Google ID
func TestUserWithGoogleID(googleID string) *models.User {
	user := TestUser()
	user.GoogleID = googleID
	return user
}

// TestUserWithID creates a test user with a specific ID
func TestUserWithID(id uuid.UUID) *models.User {
	user := TestUser()
	user.ID = id
	return user
}

// TestSessionInfo creates a test session info
func TestSessionInfo(userID uuid.UUID) *models.SessionInfo {
	return &models.SessionInfo{
		ID:         uuid.New().String(),
		DeviceInfo: "Chrome 120 · Windows 11 · Desktop",
		IPAddress:  "203.0.113.42",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
	}
}

// TimePtr returns a pointer to the given time
func TimePtr(t time.Time) *time.Time {
	return &t
}

// StringPtr returns a pointer to the given string
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to the given int
func IntPtr(i int) *int {
	return &i
}

// UserAgents provides common user agent strings for testing
var UserAgents = struct {
	Chrome       string
	Safari       string
	Firefox      string
	Edge         string
	MobileChrome string
	MobileSafari string
	Unknown      string
}{
	Chrome:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	Safari:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	Firefox:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	Edge:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	MobileChrome: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	MobileSafari: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	Unknown:      "",
}

// IPAddresses provides test IP addresses
var IPAddresses = struct {
	Public     string
	Private    string
	Localhost  string
	Private10  string
	Private172 string
}{
	Public:     "203.0.113.42",
	Private:    "192.168.1.100",
	Localhost:  "127.0.0.1",
	Private10:  "10.0.0.1",
	Private172: "172.16.0.1",
}
