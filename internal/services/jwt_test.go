package services

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/internal/testutil"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupJWTService(t *testing.T) (*JWTService, *miniredis.Miniredis, func()) {
	t.Helper()

	mr, cleanup := testutil.SetupMiniRedis(t)
	redisDB := testutil.NewTestRedisDB(t, mr)

	cfg := &config.JWTConfig{
		Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	jwtService := NewJWTService(cfg, redisDB)

	return jwtService, mr, func() {
		cleanup()
		redisDB.Close()
	}
}

func TestGenerateTokenPair(t *testing.T) {
	jwtService, _, cleanup := setupJWTService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	t.Run("generates valid token pair", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)
		require.NotNil(t, tokens)

		// Check token fields
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.False(t, tokens.ExpiresAt.IsZero())

		// Check expiration time is in the future
		assert.True(t, tokens.ExpiresAt.After(time.Now()))
	})

	t.Run("tokens contain correct claims", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Validate access token claims
		claims, err := jwtService.ValidateToken(ctx, tokens.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), claims.UserID)
		assert.Equal(t, email, claims.Email)
		assert.NotEmpty(t, claims.JTI)

		// Validate refresh token claims
		refreshClaims, err := jwtService.ValidateToken(ctx, tokens.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), refreshClaims.UserID)
		assert.Equal(t, email, refreshClaims.Email)
		assert.NotEmpty(t, refreshClaims.JTI)
	})

	t.Run("each token has unique JTI", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		accessClaims, err := jwtService.ValidateToken(ctx, tokens.AccessToken)
		require.NoError(t, err)

		refreshClaims, err := jwtService.ValidateToken(ctx, tokens.RefreshToken)
		require.NoError(t, err)

		assert.NotEqual(t, accessClaims.JTI, refreshClaims.JTI)
	})

	t.Run("refresh token is stored in Redis", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		refreshClaims, err := jwtService.ValidateToken(ctx, tokens.RefreshToken)
		require.NoError(t, err)

		// Try to get refresh token from Redis
		storedUserID, err := jwtService.redis.GetRefreshToken(ctx, refreshClaims.JTI)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), storedUserID)
	})
}

func TestValidateToken(t *testing.T) {
	jwtService, mr, cleanup := setupJWTService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	t.Run("accepts valid token", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		claims, err := jwtService.ValidateToken(ctx, tokens.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), claims.UserID)
		assert.Equal(t, email, claims.Email)
	})

	t.Run("rejects token with invalid signature", func(t *testing.T) {
		// Create a token with different secret
		wrongCfg := &config.JWTConfig{
			Secret:        []byte("wrong-secret-key-different-value!!"),
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 7 * 24 * time.Hour,
		}
		wrongRedisDB := testutil.NewTestRedisDB(t, mr)
		defer wrongRedisDB.Close()

		wrongService := NewJWTService(wrongCfg, wrongRedisDB)
		tokens, err := wrongService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Try to validate with correct service
		_, err = jwtService.ValidateToken(ctx, tokens.AccessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Create service with very short expiry
		shortCfg := &config.JWTConfig{
			Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
			AccessExpiry:  1 * time.Millisecond,
			RefreshExpiry: 1 * time.Millisecond,
		}
		shortRedisDB := testutil.NewTestRedisDB(t, mr)
		defer shortRedisDB.Close()

		shortService := NewJWTService(shortCfg, shortRedisDB)
		tokens, err := shortService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		_, err = shortService.ValidateToken(ctx, tokens.AccessToken)
		assert.Error(t, err)
	})

	t.Run("rejects blacklisted token", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Blacklist the token
		err = jwtService.RevokeToken(ctx, tokens.AccessToken)
		require.NoError(t, err)

		// Try to validate
		_, err = jwtService.ValidateToken(ctx, tokens.AccessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		malformedTokens := []string{
			"not.a.jwt",
			"",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
		}

		for _, token := range malformedTokens {
			_, err := jwtService.ValidateToken(ctx, token)
			assert.Error(t, err, "Should reject token: %s", token)
		}
	})
}

func TestRefreshAccessToken(t *testing.T) {
	jwtService, _, cleanup := setupJWTService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	t.Run("generates new token pair with valid refresh token", func(t *testing.T) {
		// Generate initial tokens
		oldTokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Refresh tokens
		newTokens, err := jwtService.RefreshAccessToken(ctx, oldTokens.RefreshToken)
		require.NoError(t, err)
		require.NotNil(t, newTokens)

		// New tokens should be different
		assert.NotEqual(t, oldTokens.AccessToken, newTokens.AccessToken)
		assert.NotEqual(t, oldTokens.RefreshToken, newTokens.RefreshToken)

		// New tokens should be valid
		claims, err := jwtService.ValidateToken(ctx, newTokens.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), claims.UserID)
		assert.Equal(t, email, claims.Email)
	})

	t.Run("invalidates old refresh token (rotation)", func(t *testing.T) {
		// Generate initial tokens
		oldTokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Refresh tokens
		_, err = jwtService.RefreshAccessToken(ctx, oldTokens.RefreshToken)
		require.NoError(t, err)

		// Try to use old refresh token again
		_, err = jwtService.RefreshAccessToken(ctx, oldTokens.RefreshToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
	})

	t.Run("fails with invalid refresh token", func(t *testing.T) {
		_, err := jwtService.RefreshAccessToken(ctx, "invalid.token.here")
		assert.Error(t, err)
	})

	t.Run("fails with access token (not refresh token)", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Try to refresh with access token
		_, err = jwtService.RefreshAccessToken(ctx, tokens.AccessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found or expired")
	})

	t.Run("fails with expired refresh token", func(t *testing.T) {
		// Create service with very short expiry
		shortCfg := &config.JWTConfig{
			Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
			AccessExpiry:  1 * time.Millisecond,
			RefreshExpiry: 1 * time.Millisecond,
		}
		mr, cleanup := testutil.SetupMiniRedis(t)
		defer cleanup()
		shortRedisDB := testutil.NewTestRedisDB(t, mr)
		defer shortRedisDB.Close()

		shortService := NewJWTService(shortCfg, shortRedisDB)
		tokens, err := shortService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		_, err = shortService.RefreshAccessToken(ctx, tokens.RefreshToken)
		assert.Error(t, err)
	})
}

func TestRevokeToken(t *testing.T) {
	jwtService, _, cleanup := setupJWTService(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	t.Run("blacklists valid token", func(t *testing.T) {
		tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Token should be valid before revocation
		_, err = jwtService.ValidateToken(ctx, tokens.AccessToken)
		require.NoError(t, err)

		// Revoke token
		err = jwtService.RevokeToken(ctx, tokens.AccessToken)
		require.NoError(t, err)

		// Token should be invalid after revocation
		_, err = jwtService.ValidateToken(ctx, tokens.AccessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("does not error on already expired token", func(t *testing.T) {
		// Create service with very short expiry
		shortCfg := &config.JWTConfig{
			Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
			AccessExpiry:  1 * time.Millisecond,
			RefreshExpiry: 1 * time.Millisecond,
		}
		mr, cleanup := testutil.SetupMiniRedis(t)
		defer cleanup()
		shortRedisDB := testutil.NewTestRedisDB(t, mr)
		defer shortRedisDB.Close()

		shortService := NewJWTService(shortCfg, shortRedisDB)
		tokens, err := shortService.GenerateTokenPair(ctx, userID, email)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		// Should not error when revoking expired token
		err = shortService.RevokeToken(ctx, tokens.AccessToken)
		assert.NoError(t, err)
	})

	t.Run("handles invalid token gracefully", func(t *testing.T) {
		// Should not panic or error on malformed token
		err := jwtService.RevokeToken(ctx, "invalid.token.string")
		assert.NoError(t, err)
	})
}

func TestGenerateJTI(t *testing.T) {
	t.Run("generates non-empty string", func(t *testing.T) {
		jti := generateJTI()
		assert.NotEmpty(t, jti)
	})

	t.Run("generates unique JTIs", func(t *testing.T) {
		jti1 := generateJTI()
		jti2 := generateJTI()
		assert.NotEqual(t, jti1, jti2)
	})

	t.Run("generates multiple unique JTIs", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			jti := generateJTI()
			assert.False(t, seen[jti], "JTI collision detected: %s", jti)
			seen[jti] = true
		}
	})
}

func TestGenerateState(t *testing.T) {
	t.Run("generates non-empty string", func(t *testing.T) {
		state := GenerateState()
		assert.NotEmpty(t, state)
	})

	t.Run("generates unique states", func(t *testing.T) {
		state1 := GenerateState()
		state2 := GenerateState()
		assert.NotEqual(t, state1, state2)
	})

	t.Run("generates multiple unique states", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			state := GenerateState()
			assert.False(t, seen[state], "State collision detected: %s", state)
			seen[state] = true
		}
	})
}

func TestJWTServiceConcurrency(t *testing.T) {
	jwtService, _, cleanup := setupJWTService(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("concurrent token generation", func(t *testing.T) {
		const goroutines = 10
		done := make(chan bool, goroutines)
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				userID := uuid.New()
				email := "test@example.com"

				tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
				if err != nil {
					errors <- err
					return
				}

				// Validate the token
				_, err = jwtService.ValidateToken(ctx, tokens.AccessToken)
				if err != nil {
					errors <- err
					return
				}

				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < goroutines; i++ {
			select {
			case <-done:
				// Success
			case err := <-errors:
				t.Fatalf("Concurrent operation failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations")
			}
		}
	})
}

// Benchmark tests
func BenchmarkGenerateTokenPair(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	cfg := &config.RedisConfig{
		Host:     mr.Host(),
		Port:     mr.Port(),
		Password: "",
		DB:       0,
	}

	redisDB, err := database.NewRedisDB(cfg)
	if err != nil {
		b.Fatalf("Failed to create Redis DB: %v", err)
	}
	defer redisDB.Close()

	jwtCfg := &config.JWTConfig{
		Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	jwtService := NewJWTService(jwtCfg, redisDB)
	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwtService.GenerateTokenPair(ctx, userID, email)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateToken(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	cfg := &config.RedisConfig{
		Host:     mr.Host(),
		Port:     mr.Port(),
		Password: "",
		DB:       0,
	}

	redisDB, err := database.NewRedisDB(cfg)
	if err != nil {
		b.Fatalf("Failed to create Redis DB: %v", err)
	}
	defer redisDB.Close()

	jwtCfg := &config.JWTConfig{
		Secret:        []byte("test-secret-key-min-32-bytes-long!!"),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	jwtService := NewJWTService(jwtCfg, redisDB)
	ctx := context.Background()
	userID := uuid.New()
	email := "test@example.com"

	tokens, err := jwtService.GenerateTokenPair(ctx, userID, email)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwtService.ValidateToken(ctx, tokens.AccessToken)
		if err != nil {
			b.Fatal(err)
		}
	}
}
