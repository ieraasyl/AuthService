package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/pkg/cache"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/mileusna/useragent"
	"github.com/rs/zerolog/log"
)

// SessionStore defines the interface for session storage operations.
// This interface abstracts Redis operations for session management,
// enabling testing and dependency injection.
type SessionStore interface {
	SetSession(ctx context.Context, userID, sessionID, deviceInfo, ipAddress string, expiry time.Duration) error
	GetSession(ctx context.Context, userID, sessionID string) (map[string]string, error)
	ListUserSessions(ctx context.Context, userID string) ([]string, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
}

// SessionService handles user session management and tracking.
// It provides functionality for:
//   - Creating and tracking user sessions
//   - Listing active sessions per user
//   - Revoking individual or all sessions
//   - Extracting device information from User-Agent headers
//   - Geolocation lookup with caching
//
// Sessions are stored in Redis with automatic expiration and include
// metadata like device type, IP address, and creation time for security
// and user experience features.
type SessionService struct {
	redis         SessionStore  // Redis for session persistence
	cache         *cache.Cache  // Cache for geolocation data
	sessionExpiry time.Duration // Session lifetime (default: 7 days)
}

// NewSessionService creates a new session service with the specified configuration.
//
// Parameters:
//   - redis: Session store implementation (typically RedisDB)
//   - cache: Cache for geolocation data to reduce API calls
//   - sessionExpiry: How long sessions remain valid (e.g., 7*24*time.Hour)
//
// Example:
//
//	sessionSvc := services.NewSessionService(
//	    redisDB,
//	    cacheInstance,
//	    7*24*time.Hour, // 7 days
//	)
func NewSessionService(redis SessionStore, cache *cache.Cache, sessionExpiry time.Duration) *SessionService {
	return &SessionService{
		redis:         redis,
		cache:         cache,
		sessionExpiry: sessionExpiry,
	}
}

// CreateSession creates a new session for a user after successful authentication.
// Generates a unique session ID and stores session metadata in Redis.
//
// Session metadata includes:
//   - Device information (browser, OS, device type)
//   - IP address for security tracking
//   - Creation timestamp
//   - Automatic expiration
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the authenticated user
//   - deviceInfo: Parsed User-Agent string (use ExtractDeviceInfo)
//   - ipAddress: Client IP address (use utils.ExtractClientIP)
//
// Returns the generated session ID or an error if creation fails.
//
// Example:
//
//	deviceInfo := services.ExtractDeviceInfo(r.UserAgent())
//	ipAddress := utils.ExtractClientIP(r)
//	sessionID, err := sessionSvc.CreateSession(ctx, user.ID, deviceInfo, ipAddress)
//	if err != nil {
//	    return fmt.Errorf("session creation failed: %w", err)
//	}
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, deviceInfo, ipAddress string) (string, error) {
	sessionID := uuid.New().String()

	err := s.redis.SetSession(ctx, userID.String(), sessionID, deviceInfo, ipAddress, s.sessionExpiry)
	if err != nil {
		log.Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("Failed to create session")
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	log.Info().
		Str("user_id", userID.String()).
		Str("session_id", sessionID).
		Str("device", deviceInfo).
		Msg("Session created successfully")

	return sessionID, nil
}

// GetSession retrieves detailed information about a specific session.
// Returns SessionInfo with sanitized data (no sensitive tokens).
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the session owner
//   - sessionID: The session identifier to retrieve
//
// Returns the session information or an error if not found or expired.
//
// Example:
//
//	sessionInfo, err := sessionSvc.GetSession(ctx, userID, sessionID)
//	if err != nil {
//	    return nil, errors.New("session not found")
//	}
//	fmt.Printf("Session from %s expires at %s\n",
//	    sessionInfo.IPAddress, sessionInfo.ExpiresAt)
func (s *SessionService) GetSession(ctx context.Context, userID uuid.UUID, sessionID string) (*models.SessionInfo, error) {
	sessionData, err := s.redis.GetSession(ctx, userID.String(), sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Parse created_at timestamp
	createdAtUnix, err := strconv.ParseInt(sessionData["created_at"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid session data: %w", err)
	}
	createdAt := time.Unix(createdAtUnix, 0)

	sessionInfo := &models.SessionInfo{
		ID:         sessionID,
		DeviceInfo: sessionData["device_info"],
		IPAddress:  sessionData["ip_address"],
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(s.sessionExpiry),
	}

	return sessionInfo, nil
}

// ListUserSessions returns all active sessions for a user.
// This is used for the "active sessions" feature where users can view
// and manage their login sessions across different devices.
//
// Invalid or expired sessions are skipped (logged but not returned).
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the user whose sessions to list
//
// Returns a slice of SessionInfo for all active sessions, or an error
// if the operation fails.
//
// Example:
//
//	sessions, err := sessionSvc.ListUserSessions(ctx, userID)
//	if err != nil {
//	    return nil, err
//	}
//	for _, session := range sessions {
//	    fmt.Printf("Device: %s, Location: %s\n",
//	        session.DeviceInfo, session.IPAddress)
//	}
func (s *SessionService) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.SessionInfo, error) {
	sessionIDs, err := s.redis.ListUserSessions(ctx, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]*models.SessionInfo, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		sessionInfo, err := s.GetSession(ctx, userID, sessionID)
		if err != nil {
			// Skip invalid sessions
			log.Warn().
				Err(err).
				Str("user_id", userID.String()).
				Str("session_id", sessionID).
				Msg("Failed to get session info")
			continue
		}
		sessions = append(sessions, sessionInfo)
	}

	return sessions, nil
}

// RevokeSession deletes a specific session, effectively logging out that device.
// This is used when users want to log out a specific device/session while
// keeping others active.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the session owner
//   - sessionID: The session identifier to revoke
//
// Returns an error if the revocation fails.
//
// Example:
//
//	// User clicks "Log out this device" in sessions list
//	if err := sessionSvc.RevokeSession(ctx, userID, sessionID); err != nil {
//	    return fmt.Errorf("failed to revoke session: %w", err)
//	}
func (s *SessionService) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID string) error {
	err := s.redis.DeleteSession(ctx, userID.String(), sessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	log.Info().
		Str("user_id", userID.String()).
		Str("session_id", sessionID).
		Msg("Session revoked successfully")

	return nil
}

// RevokeAllSessions deletes all sessions for a user, logging them out everywhere.
// This is used for:
//   - "Log out all devices" functionality
//   - Security responses (password change, suspicious activity)
//   - Account deletion
//
// Individual session deletion failures are logged but don't stop the process.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the user whose sessions to revoke
//
// Returns an error if the operation fails to list sessions.
//
// Example:
//
//	// After password change
//	if err := sessionSvc.RevokeAllSessions(ctx, userID); err != nil {
//	    log.Error().Err(err).Msg("Failed to revoke all sessions")
//	}
//	// User must log in again on all devices
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	sessionIDs, err := s.redis.ListUserSessions(ctx, userID.String())
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	for _, sessionID := range sessionIDs {
		if err := s.redis.DeleteSession(ctx, userID.String(), sessionID); err != nil {
			log.Warn().
				Err(err).
				Str("user_id", userID.String()).
				Str("session_id", sessionID).
				Msg("Failed to delete session")
		}
	}

	log.Info().
		Str("user_id", userID.String()).
		Int("count", len(sessionIDs)).
		Msg("All sessions revoked")

	return nil
}

// ExtractDeviceInfo extracts human-readable device information from a User-Agent header.
// Parses the User-Agent to identify browser, operating system, and device type,
// formatting it into a friendly string for display in session lists.
//
// Parameters:
//   - userAgent: The User-Agent header string from the HTTP request
//
// Returns a formatted string like "Chrome 120 · Windows 11 · Desktop" or
// "Unknown Device" if the User-Agent is empty.
//
// Example:
//
//	deviceInfo := services.ExtractDeviceInfo(r.UserAgent())
//	// Returns: "Chrome 120.0 · Windows 11 · Desktop"
//	// Or: "Safari 17.0 · iOS 17.1 · Mobile"
func ExtractDeviceInfo(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	ua := useragent.Parse(userAgent)

	// Build friendly device string
	var parts []string

	// Browser
	if ua.Name != "" {
		browser := ua.Name
		if ua.Version != "" {
			browser += " " + ua.Version
		}
		parts = append(parts, browser)
	}

	// Operating System
	if ua.OS != "" {
		os := ua.OS
		if ua.OSVersion != "" {
			os += " " + ua.OSVersion
		}
		parts = append(parts, os)
	}

	// Device type
	if ua.Mobile {
		parts = append(parts, "Mobile")
	} else if ua.Tablet {
		parts = append(parts, "Tablet")
	} else if ua.Desktop {
		parts = append(parts, "Desktop")
	}

	if len(parts) == 0 {
		// Fallback to truncated user agent
		if len(userAgent) > 100 {
			return userAgent[:100] + "..."
		}
		return userAgent
	}

	return strings.Join(parts, " · ")
}

// GeoLocation represents geolocation information from the IP geolocation API.
// This struct matches the response format from ip-api.com.
type GeoLocation struct {
	Country     string `json:"country"`     // Full country name (e.g., "United States")
	CountryCode string `json:"countryCode"` // ISO 3166-1 alpha-2 code (e.g., "US")
	Region      string `json:"region"`      // Region/state code (e.g., "CA")
	RegionName  string `json:"regionName"`  // Full region name (e.g., "California")
	City        string `json:"city"`        // City name (e.g., "Los Angeles")
	Timezone    string `json:"timezone"`    // Timezone (e.g., "America/Los_Angeles")
}

// GetGeoLocation fetches geolocation information for an IP address with caching.
// Uses ip-api.com free service (rate limit: 45 requests/minute) and caches
// results for 24 hours to minimize API calls.
//
// Returns a formatted location string like "San Francisco, 🇺🇸 United States"
// or "Local Network" for private IPs, or just the IP address if lookup fails.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - ipAddress: The IP address to look up
//
// Returns a human-readable location string.
//
// Example:
//
//	location := sessionSvc.GetGeoLocation(ctx, "8.8.8.8")
//	// Returns: "Mountain View, 🇺🇸 United States"
//
//	location := sessionSvc.GetGeoLocation(ctx, "192.168.1.1")
//	// Returns: "Local Network"
func (s *SessionService) GetGeoLocation(ctx context.Context, ipAddress string) string {
	// Skip private/local IPs using centralized utility
	if utils.IsPrivateIP(ipAddress) {
		return "Local Network"
	}

	// Check cache first
	cacheKey := cache.GeoLocationKey(ipAddress)
	var cachedLocation string

	err := s.cache.Get(ctx, cacheKey, &cachedLocation)
	if err == nil {
		log.Debug().Str("ip", ipAddress).Msg("Geolocation cache hit")
		return cachedLocation
	}

	// If error is not cache miss, log and continue to fetch
	if err != cache.ErrCacheMiss {
		log.Warn().Err(err).Str("ip", ipAddress).Msg("Failed to get from cache, fetching")
	}

	// Fetch from API
	location := s.fetchGeoLocationFromAPI(ipAddress)

	// Cache the result with 24-hour TTL
	if err := s.cache.Set(ctx, cacheKey, location, 24*time.Hour); err != nil {
		log.Warn().Err(err).Str("ip", ipAddress).Msg("Failed to cache geolocation")
	}

	log.Debug().Str("ip", ipAddress).Str("location", location).Msg("Geolocation fetched and cached")
	return location
}

// fetchGeoLocationFromAPI retrieves geolocation data from ip-api.com.
// This is an internal helper called by GetGeoLocation when cache misses occur.
//
// Uses the free ip-api.com service which provides:
//   - No API key required
//   - 45 requests per minute rate limit
//   - Returns country, region, city, timezone
//
// Parameters:
//   - ipAddress: The IP address to look up
//
// Returns a formatted location string or the original IP if lookup fails.
func (s *SessionService) fetchGeoLocationFromAPI(ipAddress string) string {
	// Use free ip-api.com service (no API key required for non-commercial use)
	// Rate limit: 45 requests per minute
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,timezone", ipAddress)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		// Return IP without location info on error
		return ipAddress
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ipAddress
	}

	var result struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Return IP without location info on decode error
		return ipAddress
	}

	if result.Status != "success" {
		return ipAddress
	}

	// Build location string
	var location []string
	if result.City != "" {
		location = append(location, result.City)
	}
	if result.Country != "" {
		flag := countryCodeToFlag(result.CountryCode)
		location = append(location, flag+" "+result.Country)
	}

	if len(location) == 0 {
		return ipAddress
	}

	return strings.Join(location, ", ")
}

// countryCodeToFlag converts an ISO 3166-1 alpha-2 country code to an emoji flag.
// Uses Unicode Regional Indicator Symbols (U+1F1E6 - U+1F1FF) to construct flags.
//
// Parameters:
//   - code: Two-letter country code (e.g., "US", "GB", "JP")
//
// Returns the corresponding flag emoji (e.g., "🇺🇸", "🇬🇧", "🇯🇵") or empty string
// if the code is invalid.
//
// Example:
//
//	flag := countryCodeToFlag("US") // Returns: "🇺🇸"
//	flag := countryCodeToFlag("FR") // Returns: "🇫🇷"
func countryCodeToFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	// Convert country code to regional indicator symbols
	// A = U+1F1E6, B = U+1F1E7, etc.
	flag := ""
	for _, r := range code {
		if r >= 'A' && r <= 'Z' {
			flag += string(rune(0x1F1E6 + (r - 'A')))
		}
	}
	return flag
}
