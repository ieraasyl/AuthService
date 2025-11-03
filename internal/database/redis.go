package database

import (
	"context"
	"fmt"
	"time"

	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// RedisDB wraps a Redis client for high-performance caching and session storage.
// Provides type-safe methods for common operations including:
//   - Refresh token storage and validation
//   - Session management with automatic expiration
//   - Token blacklisting for revocation
//   - Rate limiting per IP address
//
// All keys use structured naming patterns for organization and monitoring.
type RedisDB struct {
	client *redis.Client // Underlying Redis client with connection pooling
}

// NewRedisDB creates a new Redis connection with automatic retry.
// Implements exponential backoff retry logic similar to PostgreSQL connection.
//
// Connection pool settings:
//   - PoolSize: From configuration (default: 100)
//   - Automatic connection health monitoring
//   - Reconnection on failures
//
// Retry configuration:
//   - Max attempts: 5
//   - Initial delay: 100ms
//   - Max delay: 3 seconds
//   - Total timeout: 30 seconds
//
// Parameters:
//   - cfg: Redis configuration including host, port, password, database, and pool size
//
// Returns the connected Redis client or an error if all retries fail.
//
// Example:
//
//	redisDB, err := database.NewRedisDB(&config.RedisConfig{
//	    Host:     "localhost",
//	    Port:     "6379",
//	    Password: "",
//	    DB:       0,
//	    PoolSize: 100,
//	})
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Redis connection failed")
//	}
//	defer redisDB.Close()
func NewRedisDB(cfg *config.RedisConfig) (*RedisDB, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address(),
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	})

	// Verify connection with retry
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	retryConfig := utils.DatabaseRetryConfig()
	retryConfig.MaxAttempts = 5
	retryConfig.InitialDelay = 100 * time.Millisecond
	retryConfig.MaxDelay = 3 * time.Second

	var lastErr error
	err := utils.Retry(ctx, retryConfig, func() error {
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pingCancel()

		if err := client.Ping(pingCtx).Err(); err != nil {
			lastErr = err
			log.Warn().Err(err).Msg("Failed to ping Redis, retrying...")
			return err
		}
		return nil
	})

	if err != nil {
		client.Close()
		if lastErr != nil {
			return nil, fmt.Errorf("failed to connect to Redis after retries: %w", lastErr)
		}
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info().Msg("Successfully connected to Redis")

	return &RedisDB{client: client}, nil
}

// Close closes the Redis connection and releases all resources.
// Should be called when shutting down the application.
//
// Example:
//
//	redisDB, err := database.NewRedisDB(cfg)
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Failed to connect")
//	}
//	defer redisDB.Close()
func (r *RedisDB) Close() error {
	return r.client.Close()
}

// Client returns the underlying Redis client for advanced operations.
// Use this when you need to perform Redis operations not covered by
// the wrapper methods.
//
// Example:
//
//	client := redisDB.Client()
//	result, err := client.ZRange(ctx, "leaderboard", 0, 10).Result()
func (r *RedisDB) Client() *redis.Client {
	return r.client
}

// Ping checks if Redis is alive and responsive.
// Used by health check endpoints to verify Redis availability.
//
// Returns an error if Redis is unreachable or not responding.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
//	defer cancel()
//	if err := redisDB.Ping(ctx); err != nil {
//	    return "unhealthy", err
//	}
func (r *RedisDB) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// SetRefreshToken stores a refresh token ID mapped to a user ID.
// Used for token refresh validation - the token ID (JTI) is stored
// as the key, and the user ID as the value.
//
// Key pattern: "refresh_token:{tokenID}"
//
// The entry automatically expires after the specified duration,
// matching the token's expiration time.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tokenID: Unique token identifier (JWT's JTI claim)
//   - userID: User's UUID as string
//   - expiry: How long the token is valid (e.g., 7 days)
//
// Example:
//
//	err := redisDB.SetRefreshToken(ctx,
//	    "token-abc-123",
//	    "550e8400-e29b-41d4-a716-446655440000",
//	    7*24*time.Hour,
//	)
func (r *RedisDB) SetRefreshToken(ctx context.Context, tokenID, userID string, expiry time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s", tokenID)
	err := r.client.Set(ctx, key, userID, expiry).Err()
	if err != nil {
		return fmt.Errorf("failed to set refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken retrieves the user ID associated with a refresh token.
// Returns an error if the token doesn't exist or has expired.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tokenID: Unique token identifier to look up
//
// Returns the user ID string or an error if not found.
//
// Example:
//
//	userID, err := redisDB.GetRefreshToken(ctx, "token-abc-123")
//	if err != nil {
//	    return nil, errors.New("invalid or expired refresh token")
//	}
func (r *RedisDB) GetRefreshToken(ctx context.Context, tokenID string) (string, error) {
	key := fmt.Sprintf("refresh_token:%s", tokenID)
	userID, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}
	return userID, nil
}

// DeleteRefreshToken removes a refresh token from storage.
// Called during token rotation to invalidate the old token.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tokenID: Token identifier to delete
//
// Example:
//
//	// After issuing new token, delete old one
//	if err := redisDB.DeleteRefreshToken(ctx, oldTokenID); err != nil {
//	    log.Warn().Err(err).Msg("Failed to delete old token")
//	}
func (r *RedisDB) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	key := fmt.Sprintf("refresh_token:%s", tokenID)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

// SetSession stores session information as a Redis hash.
// Sessions include device info, IP address, and creation timestamp.
//
// Key pattern: "session:{userID}:{sessionID}"
//
// The session automatically expires after the specified duration.
// Sessions are used for multi-device tracking and security features.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: User's UUID
//   - sessionID: Unique session identifier
//   - deviceInfo: Device/browser info (from User-Agent)
//   - ipAddress: Client IP address
//   - expiry: Session lifetime (e.g., 7 days)
//
// Example:
//
//	err := redisDB.SetSession(ctx,
//	    userID.String(),
//	    sessionID,
//	    "Chrome 120 · Windows 11 · Desktop",
//	    "203.0.113.42",
//	    7*24*time.Hour,
//	)
func (r *RedisDB) SetSession(ctx context.Context, userID, sessionID, deviceInfo, ipAddress string, expiry time.Duration) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	sessionData := map[string]interface{}{
		"device_info": deviceInfo,
		"ip_address":  ipAddress,
		"created_at":  time.Now().Unix(),
	}

	err := r.client.HSet(ctx, key, sessionData).Err()
	if err != nil {
		return fmt.Errorf("failed to set session: %w", err)
	}

	// Set expiration
	err = r.client.Expire(ctx, key, expiry).Err()
	if err != nil {
		return fmt.Errorf("failed to set session expiry: %w", err)
	}

	return nil
}

// GetSession retrieves session information from Redis.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: User's UUID
//   - sessionID: Session identifier
//
// Returns a map with session data (device_info, ip_address, created_at)
// or an error if the session doesn't exist or has expired.
//
// Example:
//
//	sessionData, err := redisDB.GetSession(ctx, userID.String(), sessionID)
//	if err != nil {
//	    return nil, errors.New("session not found")
//	}
//	deviceInfo := sessionData["device_info"]
func (r *RedisDB) GetSession(ctx context.Context, userID, sessionID string) (map[string]string, error) {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("session not found")
	}
	return result, nil
}

// DeleteSession removes a session from Redis.
// Called when a user logs out from a specific device.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: User's UUID
//   - sessionID: Session identifier to delete
//
// Example:
//
//	// User clicks "Log out this device"
//	if err := redisDB.DeleteSession(ctx, userID.String(), sessionID); err != nil {
//	    return fmt.Errorf("failed to delete session: %w", err)
//	}
func (r *RedisDB) DeleteSession(ctx context.Context, userID, sessionID string) error {
	key := fmt.Sprintf("session:%s:%s", userID, sessionID)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// ListUserSessions returns all session IDs for a user using SCAN.
// Uses SCAN instead of KEYS to avoid blocking Redis in production.
// Scans in batches of 100 keys for efficient iteration.
//
// Key pattern: "session:{userID}:*"
//
// SCAN is production-safe:
//   - Non-blocking (doesn't lock Redis)
//   - Cursor-based iteration
//   - Handles large key spaces efficiently
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: User's UUID
//
// Returns a slice of session IDs (just the ID part, not the full key).
//
// Example:
//
//	sessionIDs, err := redisDB.ListUserSessions(ctx, userID.String())
//	if err != nil {
//	    return nil, err
//	}
//	fmt.Printf("User has %d active sessions\n", len(sessionIDs))
func (r *RedisDB) ListUserSessions(ctx context.Context, userID string) ([]string, error) {
	pattern := fmt.Sprintf("session:%s:*", userID)
	prefix := fmt.Sprintf("session:%s:", userID)

	var sessions []string
	var cursor uint64

	// Use SCAN instead of KEYS to avoid blocking Redis
	for {
		var keys []string
		var err error

		// Scan with batch size of 100
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan sessions: %w", err)
		}

		// Extract session IDs from keys
		for _, key := range keys {
			if len(key) > len(prefix) {
				sessionID := key[len(prefix):]
				sessions = append(sessions, sessionID)
			}
		}

		// Break when cursor returns to 0 (full iteration complete)
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

// BlacklistToken adds a token to the blacklist for revocation.
// Blacklisted tokens are rejected even if they have valid signatures.
//
// Key pattern: "blacklist:{jti}"
//
// The blacklist entry automatically expires when the token would
// naturally expire, preventing unbounded memory growth.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - jti: JWT ID (unique token identifier)
//   - expiry: Remaining token lifetime (time until natural expiration)
//
// Example:
//
//	// Calculate remaining TTL
//	ttl := time.Until(tokenClaims.ExpiresAt.Time)
//	if ttl > 0 {
//	    err := redisDB.BlacklistToken(ctx, tokenClaims.JTI, ttl)
//	}
func (r *RedisDB) BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error {
	key := fmt.Sprintf("blacklist:%s", jti)
	err := r.client.Set(ctx, key, "true", expiry).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}
	return nil
}

// IsTokenBlacklisted checks if a token has been revoked.
// Should be called during JWT validation to enforce revocation.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - jti: JWT ID to check
//
// Returns true if the token is blacklisted, false otherwise.
//
// Example:
//
//	blacklisted, err := redisDB.IsTokenBlacklisted(ctx, claims.JTI)
//	if err != nil {
//	    return fmt.Errorf("blacklist check failed: %w", err)
//	}
//	if blacklisted {
//	    return errors.New("token has been revoked")
//	}
func (r *RedisDB) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", jti)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}
	return exists > 0, nil
}

// IncrementRateLimit increments the rate limit counter for an IP+endpoint.
// Implements a sliding window rate limiter with automatic expiration.
//
// Key pattern: "ratelimit:{ip}:{endpoint}"
//
// Behavior:
//   - First request: Sets counter to 1 and starts expiry timer
//   - Subsequent requests: Increments counter
//   - After window expires: Counter resets automatically
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - ip: Client IP address
//   - endpoint: Endpoint identifier (e.g., "login", "api")
//   - window: Time window duration (e.g., 1 minute)
//
// Returns the current count (including this request).
//
// Example:
//
//	count, err := redisDB.IncrementRateLimit(ctx,
//	    "203.0.113.42",
//	    "login",
//	    1*time.Minute,
//	)
//	if count > 60 {
//	    return errors.New("rate limit exceeded")
//	}
func (r *RedisDB) IncrementRateLimit(ctx context.Context, ip, endpoint string, window time.Duration) (int64, error) {
	key := fmt.Sprintf("ratelimit:%s:%s", ip, endpoint)

	// Increment counter
	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment rate limit: %w", err)
	}

	// Set expiry on first request
	if count == 1 {
		err = r.client.Expire(ctx, key, window).Err()
		if err != nil {
			return 0, fmt.Errorf("failed to set rate limit expiry: %w", err)
		}
	}

	return count, nil
}

// GetRateLimitCount retrieves the current rate limit count without incrementing.
// Useful for monitoring or displaying remaining quota to users.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - ip: Client IP address
//   - endpoint: Endpoint identifier
//
// Returns the current count (0 if no record exists).
//
// Example:
//
//	count, err := redisDB.GetRateLimitCount(ctx, "203.0.113.42", "api")
//	if err != nil {
//	    return 0, err
//	}
//	remaining := 60 - count
//	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
func (r *RedisDB) GetRateLimitCount(ctx context.Context, ip, endpoint string) (int64, error) {
	key := fmt.Sprintf("ratelimit:%s:%s", ip, endpoint)
	count, err := r.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get rate limit count: %w", err)
	}
	return count, nil
}
