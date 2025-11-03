package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/testutil"
	"github.com/ieraasyl/AuthService/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSessionService(t *testing.T) (*SessionService, func()) {
	t.Helper()

	mr, cleanup := testutil.SetupMiniRedis(t)
	redisDB := testutil.NewTestRedisDB(t, mr)
	redisClient := testutil.NewTestRedisClient(t, mr)
	cacheInstance := cache.NewCache(redisClient)

	sessionService := NewSessionService(
		redisDB,
		cacheInstance,
		7*24*time.Hour, // 7 days
	)

	return sessionService, func() {
		cleanup()
		redisDB.Close()
	}
}

func TestCreateSession(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("creates session with unique ID", func(t *testing.T) {
		sessionID, err := sessionService.CreateSession(
			ctx,
			userID,
			"Chrome 120 · Windows 11 · Desktop",
			testutil.IPAddresses.Public,
		)

		require.NoError(t, err)
		assert.NotEmpty(t, sessionID)

		// Verify it's a valid UUID
		_, err = uuid.Parse(sessionID)
		assert.NoError(t, err)
	})

	t.Run("stores session data in Redis", func(t *testing.T) {
		deviceInfo := "Safari 17 · macOS 14 · Desktop"
		ipAddress := testutil.IPAddresses.Public

		sessionID, err := sessionService.CreateSession(ctx, userID, deviceInfo, ipAddress)
		require.NoError(t, err)

		// Retrieve session
		session, err := sessionService.GetSession(ctx, userID, sessionID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, session.ID)
		assert.Equal(t, deviceInfo, session.DeviceInfo)
		assert.Equal(t, ipAddress, session.IPAddress)
	})

	t.Run("creates multiple unique sessions for same user", func(t *testing.T) {
		sessionID1, err := sessionService.CreateSession(ctx, userID, "Device 1", testutil.IPAddresses.Public)
		require.NoError(t, err)

		sessionID2, err := sessionService.CreateSession(ctx, userID, "Device 2", testutil.IPAddresses.Private)
		require.NoError(t, err)

		assert.NotEqual(t, sessionID1, sessionID2)

		// Both sessions should exist
		sessions, err := sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sessions), 2)
	})
}

func TestGetSession(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("retrieves existing session", func(t *testing.T) {
		deviceInfo := "Firefox 121 · Linux · Desktop"
		ipAddress := testutil.IPAddresses.Public

		sessionID, err := sessionService.CreateSession(ctx, userID, deviceInfo, ipAddress)
		require.NoError(t, err)

		session, err := sessionService.GetSession(ctx, userID, sessionID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, session.ID)
		assert.Equal(t, deviceInfo, session.DeviceInfo)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.False(t, session.CreatedAt.IsZero())
		assert.False(t, session.ExpiresAt.IsZero())
	})

	t.Run("returns error for non-existent session", func(t *testing.T) {
		fakeSessionID := uuid.New().String()
		_, err := sessionService.GetSession(ctx, userID, fakeSessionID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("returns error for wrong user", func(t *testing.T) {
		sessionID, err := sessionService.CreateSession(ctx, userID, "Device", testutil.IPAddresses.Public)
		require.NoError(t, err)

		wrongUserID := uuid.New()
		_, err = sessionService.GetSession(ctx, wrongUserID, sessionID)
		assert.Error(t, err)
	})
}

func TestListUserSessions(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("returns empty list for user with no sessions", func(t *testing.T) {
		sessions, err := sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("returns all user sessions", func(t *testing.T) {
		// Create multiple sessions
		devices := []string{
			"Chrome 120 · Windows 11 · Desktop",
			"Safari 17 · iOS 17 · Mobile",
			"Firefox 121 · macOS 14 · Desktop",
		}

		for _, device := range devices {
			_, err := sessionService.CreateSession(ctx, userID, device, testutil.IPAddresses.Public)
			require.NoError(t, err)
		}

		sessions, err := sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, sessions, len(devices))

		// Check all device info is present
		deviceInfos := make(map[string]bool)
		for _, session := range sessions {
			deviceInfos[session.DeviceInfo] = true
		}
		for _, device := range devices {
			assert.True(t, deviceInfos[device], "Device %s should be in sessions", device)
		}
	})

	t.Run("only returns sessions for specific user", func(t *testing.T) {
		user1 := uuid.New()
		user2 := uuid.New()

		_, err := sessionService.CreateSession(ctx, user1, "User1 Device1", testutil.IPAddresses.Public)
		require.NoError(t, err)
		_, err = sessionService.CreateSession(ctx, user1, "User1 Device2", testutil.IPAddresses.Private)
		require.NoError(t, err)
		_, err = sessionService.CreateSession(ctx, user2, "User2 Device", testutil.IPAddresses.Public)
		require.NoError(t, err)

		user1Sessions, err := sessionService.ListUserSessions(ctx, user1)
		require.NoError(t, err)
		assert.Len(t, user1Sessions, 2)

		user2Sessions, err := sessionService.ListUserSessions(ctx, user2)
		require.NoError(t, err)
		assert.Len(t, user2Sessions, 1)
	})
}

func TestRevokeSession(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("removes specific session", func(t *testing.T) {
		sessionID, err := sessionService.CreateSession(ctx, userID, "Device", testutil.IPAddresses.Public)
		require.NoError(t, err)

		// Verify session exists
		_, err = sessionService.GetSession(ctx, userID, sessionID)
		require.NoError(t, err)

		// Revoke session
		err = sessionService.RevokeSession(ctx, userID, sessionID)
		require.NoError(t, err)

		// Verify session no longer exists
		_, err = sessionService.GetSession(ctx, userID, sessionID)
		assert.Error(t, err)
	})

	t.Run("does not affect other sessions", func(t *testing.T) {
		session1, err := sessionService.CreateSession(ctx, userID, "Device 1", testutil.IPAddresses.Public)
		require.NoError(t, err)
		session2, err := sessionService.CreateSession(ctx, userID, "Device 2", testutil.IPAddresses.Private)
		require.NoError(t, err)

		// Revoke first session
		err = sessionService.RevokeSession(ctx, userID, session1)
		require.NoError(t, err)

		// Second session should still exist
		_, err = sessionService.GetSession(ctx, userID, session2)
		assert.NoError(t, err)
	})
}

func TestRevokeAllSessions(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("removes all user sessions", func(t *testing.T) {
		// Create multiple sessions
		for i := 0; i < 3; i++ {
			_, err := sessionService.CreateSession(ctx, userID, "Device", testutil.IPAddresses.Public)
			require.NoError(t, err)
		}

		// Verify sessions exist
		sessions, err := sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		require.Len(t, sessions, 3)

		// Revoke all
		err = sessionService.RevokeAllSessions(ctx, userID)
		require.NoError(t, err)

		// Verify all sessions are gone
		sessions, err = sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("does not affect other users", func(t *testing.T) {
		user1 := uuid.New()
		user2 := uuid.New()

		_, err := sessionService.CreateSession(ctx, user1, "User1 Device", testutil.IPAddresses.Public)
		require.NoError(t, err)
		_, err = sessionService.CreateSession(ctx, user2, "User2 Device", testutil.IPAddresses.Public)
		require.NoError(t, err)

		// Revoke all for user1
		err = sessionService.RevokeAllSessions(ctx, user1)
		require.NoError(t, err)

		// User2 sessions should still exist
		user2Sessions, err := sessionService.ListUserSessions(ctx, user2)
		require.NoError(t, err)
		assert.Len(t, user2Sessions, 1)
	})
}

func TestExtractDeviceInfo(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  string
	}{
		{
			name:      "Chrome on Windows",
			userAgent: testutil.UserAgents.Chrome,
			expected:  "Chrome",
		},
		{
			name:      "Safari on macOS",
			userAgent: testutil.UserAgents.Safari,
			expected:  "Safari",
		},
		{
			name:      "Firefox on Windows",
			userAgent: testutil.UserAgents.Firefox,
			expected:  "Firefox",
		},
		{
			name:      "Edge on Windows",
			userAgent: testutil.UserAgents.Edge,
			expected:  "Edge",
		},
		{
			name:      "Mobile Chrome",
			userAgent: testutil.UserAgents.MobileChrome,
			expected:  "Mobile",
		},
		{
			name:      "Mobile Safari (iPhone)",
			userAgent: testutil.UserAgents.MobileSafari,
			expected:  "Mobile",
		},
		{
			name:      "Empty user agent",
			userAgent: "",
			expected:  "Unknown Device",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceInfo := ExtractDeviceInfo(tt.userAgent)
			assert.Contains(t, deviceInfo, tt.expected)
		})
	}
}

func TestGetGeoLocation(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns location for private IP", func(t *testing.T) {
		location := sessionService.GetGeoLocation(ctx, testutil.IPAddresses.Private)
		assert.Equal(t, "Local Network", location)

		location = sessionService.GetGeoLocation(ctx, testutil.IPAddresses.Localhost)
		assert.Equal(t, "Local Network", location)

		location = sessionService.GetGeoLocation(ctx, testutil.IPAddresses.Private10)
		assert.Equal(t, "Local Network", location)

		location = sessionService.GetGeoLocation(ctx, testutil.IPAddresses.Private172)
		assert.Equal(t, "Local Network", location)
	})

	t.Run("caches geolocation results", func(t *testing.T) {
		ipAddress := testutil.IPAddresses.Public

		// First call - should fetch from API
		location1 := sessionService.GetGeoLocation(ctx, ipAddress)
		assert.NotEmpty(t, location1)

		// Second call - should come from cache
		location2 := sessionService.GetGeoLocation(ctx, ipAddress)
		assert.Equal(t, location1, location2)

		// Cache key should exist
		cacheKey := cache.GeoLocationKey(ipAddress)
		var cachedLocation string
		err := sessionService.cache.Get(ctx, cacheKey, &cachedLocation)
		assert.NoError(t, err)
		assert.Equal(t, location1, cachedLocation)
	})

	// Note: We don't test actual API calls in unit tests
	// API integration would be tested in integration tests
}

func TestCountryCodeToFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"GB", "🇬🇧"},
		{"FR", "🇫🇷"},
		{"JP", "🇯🇵"},
		{"DE", "🇩🇪"},
		{"CA", "🇨🇦"},
		{"AU", "🇦🇺"},
		{"BR", "🇧🇷"},
		{"", ""},
		{"X", ""},    // Invalid
		{"ABC", ""},  // Too long
		{"us", "🇺🇸"}, // Lowercase should work
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			flag := countryCodeToFlag(tt.code)
			assert.Equal(t, tt.expected, flag)
		})
	}
}

func TestSessionServiceConcurrency(t *testing.T) {
	sessionService, cleanup := setupSessionService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	t.Run("concurrent session creation", func(t *testing.T) {
		const goroutines = 10
		done := make(chan string, goroutines)
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(index int) {
				sessionID, err := sessionService.CreateSession(
					ctx,
					userID,
					"Device",
					testutil.IPAddresses.Public,
				)
				if err != nil {
					errors <- err
					return
				}
				done <- sessionID
			}(i)
		}

		// Collect all session IDs
		sessionIDs := make(map[string]bool)
		for i := 0; i < goroutines; i++ {
			select {
			case sessionID := <-done:
				sessionIDs[sessionID] = true
			case err := <-errors:
				t.Fatalf("Concurrent session creation failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations")
			}
		}

		// All session IDs should be unique
		assert.Len(t, sessionIDs, goroutines)

		// All sessions should exist
		sessions, err := sessionService.ListUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, sessions, goroutines)
	})
}

// Benchmark tests
func BenchmarkCreateSession(b *testing.B) {
	// Create a test helper that wraps b as t
	t := &testing.T{}
	mr, cleanup := testutil.SetupMiniRedis(t)
	defer cleanup()

	redisDB := testutil.NewTestRedisDB(t, mr)
	redisClient := testutil.NewTestRedisClient(t, mr)
	defer redisDB.Close()

	cacheInstance := cache.NewCache(redisClient)
	sessionService := NewSessionService(redisDB, cacheInstance, 7*24*time.Hour)

	ctx := context.Background()
	userID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sessionService.CreateSession(ctx, userID, "Device", testutil.IPAddresses.Public)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSession(b *testing.B) {
	// Create a test helper that wraps b as t
	t := &testing.T{}
	mr, cleanup := testutil.SetupMiniRedis(t)
	defer cleanup()

	redisDB := testutil.NewTestRedisDB(t, mr)
	redisClient := testutil.NewTestRedisClient(t, mr)
	defer redisDB.Close()

	cacheInstance := cache.NewCache(redisClient)
	sessionService := NewSessionService(redisDB, cacheInstance, 7*24*time.Hour)

	ctx := context.Background()
	userID := uuid.New()
	sessionID, _ := sessionService.CreateSession(ctx, userID, "Device", testutil.IPAddresses.Public)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sessionService.GetSession(ctx, userID, sessionID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExtractDeviceInfo(b *testing.B) {
	userAgent := testutil.UserAgents.Chrome

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractDeviceInfo(userAgent)
	}
}
