package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/rs/zerolog/log"
)

// RateLimiter implements distributed rate limiting using Redis.
// Protects endpoints from abuse by limiting the number of requests
// per IP address within a time window.
//
// Features:
//   - Per-IP rate limiting
//   - Per-endpoint tracking (different limits for different endpoints)
//   - Distributed across multiple instances (Redis-backed)
//   - Automatic window expiration
//   - Standard rate limit headers (X-RateLimit-*)
//
// Redis key pattern: "ratelimit:{ip}:{endpoint}" with TTL equal to window
//
// On limit exceeded:
//   - Returns 429 Too Many Requests
//   - Sets Retry-After header
//   - Logs the violation for monitoring
type RateLimiter struct {
	redis          *database.RedisDB // Redis for distributed counters
	requestsPerMin int               // Maximum requests allowed per window
	window         time.Duration     // Time window for rate limiting
}

// NewRateLimiter creates a new rate limiter with the specified configuration.
//
// Parameters:
//   - redis: Redis database for distributed counter storage
//   - requestsPerMin: Maximum number of requests allowed per window
//   - window: Duration of the rate limit window (e.g., 1 minute)
//
// Example:
//
//	// Allow 60 requests per minute
//	limiter := middleware.NewRateLimiter(redisDB, 60, 1*time.Minute)
//
//	// Apply to sensitive endpoints
//	r.With(limiter.Limit("login")).Post("/api/auth/login", handler.Login)
func NewRateLimiter(redis *database.RedisDB, requestsPerMin int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		redis:          redis,
		requestsPerMin: requestsPerMin,
		window:         window,
	}
}

// Limit creates middleware that applies rate limiting to an endpoint.
// Each endpoint can have independent rate limits by using different
// endpoint identifiers.
//
// Process:
//  1. Extract client IP address (handles proxies and X-Forwarded-For)
//  2. Increment Redis counter for this IP+endpoint combination
//  3. Check if count exceeds limit
//  4. Return 429 if exceeded, or add rate limit headers and continue
//
// Rate limit headers (RFC 6585):
//   - X-RateLimit-Limit: Maximum requests allowed per window
//   - X-RateLimit-Remaining: Requests remaining in current window
//   - Retry-After: Seconds until rate limit resets (on 429 only)
//
// Error handling:
//   - On Redis errors, allows request through to avoid false positives
//   - Errors are logged for monitoring
//
// Parameters:
//   - endpoint: Unique identifier for this endpoint (e.g., "login", "api", "register")
//
// Example usage:
//
//	limiter := middleware.NewRateLimiter(redisDB, 60, time.Minute)
//
//	// Strict limit for authentication
//	r.With(limiter.Limit("auth")).Post("/api/auth/login", handler.Login)
//
//	// More permissive for general API
//	r.With(limiter.Limit("api")).Route("/api", func(r chi.Router) {
//	    r.Get("/users", handler.ListUsers)
//	    r.Get("/posts", handler.ListPosts)
//	})
//
//	// No rate limit for health checks
//	r.Get("/health", handler.Health)
//
// Testing rate limits:
//
//	# Make 61 requests in quick succession
//	for i in {1..61}; do curl http://localhost:8080/api/auth/login; done
//	# Last request should return 429 Too Many Requests
func (rl *RateLimiter) Limit(endpoint string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract IP address using centralized utility
			ip := utils.ExtractClientIP(r)

			// Increment rate limit counter
			count, err := rl.redis.IncrementRateLimit(r.Context(), ip, endpoint, rl.window)
			if err != nil {
				log.Error().Err(err).Str("ip", ip).Msg("Failed to check rate limit")
				// Continue on error to avoid blocking legitimate requests
				next.ServeHTTP(w, r)
				return
			}

			// Check if limit exceeded
			if count > int64(rl.requestsPerMin) {
				log.Warn().
					Str("ip", ip).
					Str("endpoint", endpoint).
					Int64("count", count).
					Msg("Rate limit exceeded")

				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.requestsPerMin))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rl.window.Seconds())))

				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			// Set rate limit headers
			remaining := rl.requestsPerMin - int(count)
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.requestsPerMin))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}
