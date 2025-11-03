package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/internal/services"
	"github.com/ieraasyl/AuthService/internal/testutil"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupJWTTest creates a JWT service with miniredis for testing
func setupJWTTest(t *testing.T) (*services.JWTService, *database.RedisDB) {
	miniRedis, cleanup := testutil.SetupMiniRedis(t)
	t.Cleanup(cleanup)

	redisDB, err := database.NewRedisDB(&config.RedisConfig{
		Host: "localhost",
		Port: miniRedis.Port(),
	})
	require.NoError(t, err)

	jwtCfg := &config.JWTConfig{
		Secret:        []byte("test-secret-key-minimum-32-bytes-long!"),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	jwtSvc := services.NewJWTService(jwtCfg, redisDB)
	return jwtSvc, redisDB
} // Test handler that echoes user info from context
func testHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r.Context())
		if !ok {
			http.Error(w, "No user ID in context", http.StatusInternalServerError)
			return
		}

		email, ok := GetUserEmail(r.Context())
		if !ok {
			http.Error(w, "No email in context", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("UserID: " + userID + ", Email: " + email))
	}
}

func TestJWTAuth(t *testing.T) {
	t.Run("accepts valid token from Authorization header", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID := uuid.New()
		email := "test@example.com"

		// Generate a real token
		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, email)
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), userID.String())
		assert.Contains(t, rec.Body.String(), email)
	})

	t.Run("accepts valid token from cookie", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID := uuid.New()
		email := "cookie@example.com"

		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, email)
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: tokens.AccessToken})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), email)
	})

	t.Run("strips Bearer prefix from Authorization header", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID := uuid.New()
		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, "bearer@example.com")
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rejects request with missing token", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)
		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "missing token")
	})

	t.Run("rejects request with invalid token", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)
		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid_token_string")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid token")
	})

	t.Run("rejects expired token", func(t *testing.T) {
		miniRedis, cleanup := testutil.SetupMiniRedis(t)
		t.Cleanup(cleanup)

		redisDB, err := database.NewRedisDB(&config.RedisConfig{
			Host: "localhost",
			Port: miniRedis.Port(),
		})
		require.NoError(t, err)

		// Create JWT service with very short expiry
		jwtCfg := &config.JWTConfig{
			Secret:        []byte("test-secret-key-minimum-32-bytes-long!"),
			AccessExpiry:  1 * time.Millisecond, // Expires immediately
			RefreshExpiry: 7 * 24 * time.Hour,
		}
		jwtSvc := services.NewJWTService(jwtCfg, redisDB)

		userID := uuid.New()
		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, "expired@example.com")
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("adds user info to request context", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID := uuid.New()
		email := "context@example.com"
		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, email)
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)

		var capturedContext context.Context
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedContext = r.Context()
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Verify context contains user info
		contextUserID, ok := GetUserID(capturedContext)
		assert.True(t, ok)
		assert.Equal(t, userID.String(), contextUserID)

		contextEmail, ok := GetUserEmail(capturedContext)
		assert.True(t, ok)
		assert.Equal(t, email, contextEmail)
	})

	t.Run("prefers Authorization header over cookie", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID1 := uuid.New()
		userID2 := uuid.New()

		tokens1, err := jwtSvc.GenerateTokenPair(context.Background(), userID1, "header@example.com")
		require.NoError(t, err)

		tokens2, err := jwtSvc.GenerateTokenPair(context.Background(), userID2, "cookie@example.com")
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens1.AccessToken)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: tokens2.AccessToken})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		// Should use header token (userID1), not cookie token (userID2)
		assert.Contains(t, rec.Body.String(), userID1.String())
		assert.NotContains(t, rec.Body.String(), userID2.String())
	})

	t.Run("rejects revoked token", func(t *testing.T) {
		jwtSvc, _ := setupJWTTest(t)

		userID := uuid.New()
		tokens, err := jwtSvc.GenerateTokenPair(context.Background(), userID, "revoked@example.com")
		require.NoError(t, err)

		// Revoke the token
		err = jwtSvc.RevokeToken(context.Background(), tokens.AccessToken)
		require.NoError(t, err)

		middleware := JWTAuth(jwtSvc)
		handler := middleware(testHandler())

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid token")
	})
}

func TestGetUserID(t *testing.T) {
	t.Run("retrieves user ID from context", func(t *testing.T) {
		userID := uuid.New().String()
		ctx := context.WithValue(context.Background(), UserIDKey, userID)

		retrievedID, ok := GetUserID(ctx)
		assert.True(t, ok)
		assert.Equal(t, userID, retrievedID)
	})

	t.Run("returns false when user ID not in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedID, ok := GetUserID(ctx)
		assert.False(t, ok)
		assert.Empty(t, retrievedID)
	})

	t.Run("returns false when user ID is wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserIDKey, 12345) // int instead of string

		retrievedID, ok := GetUserID(ctx)
		assert.False(t, ok)
		assert.Empty(t, retrievedID)
	})
}

func TestGetUserEmail(t *testing.T) {
	t.Run("retrieves email from context", func(t *testing.T) {
		email := "test@example.com"
		ctx := context.WithValue(context.Background(), UserEmailKey, email)

		retrievedEmail, ok := GetUserEmail(ctx)
		assert.True(t, ok)
		assert.Equal(t, email, retrievedEmail)
	})

	t.Run("returns false when email not in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedEmail, ok := GetUserEmail(ctx)
		assert.False(t, ok)
		assert.Empty(t, retrievedEmail)
	})

	t.Run("returns false when email is wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserEmailKey, 12345)

		retrievedEmail, ok := GetUserEmail(ctx)
		assert.False(t, ok)
		assert.Empty(t, retrievedEmail)
	})
}
