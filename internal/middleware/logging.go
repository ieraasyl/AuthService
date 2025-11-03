package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/rs/zerolog/log"
)

// CORS creates CORS middleware with configured allowed origins.
// Configures Cross-Origin Resource Sharing to allow frontend applications
// from different domains to access the API.
//
// Configuration:
//   - Allowed methods: GET, POST, PUT, DELETE, OPTIONS
//   - Allowed headers: Accept, Authorization, Content-Type, X-Request-ID
//   - Exposed headers: Link, X-RateLimit-Limit, X-RateLimit-Remaining
//   - Credentials: Enabled (allows cookies)
//   - Max age: 300 seconds (5 minutes)
//
// Parameters:
//   - allowedOrigins: List of allowed origin URLs (e.g., ["https://app.example.com"])
//
// Use "*" to allow all origins (not recommended for production with credentials).
//
// Example:
//
//	corsMiddleware := middleware.CORS([]string{
//	    "https://app.example.com",
//	    "https://staging.example.com",
//	})
//	r.Use(corsMiddleware)
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "User-Agent"},
		ExposedHeaders:   []string{"Link", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
}

// Logger creates structured logging middleware with request ID correlation.
// Logs every HTTP request and response with consistent formatting and timing.
//
// Features:
//   - Generates or uses existing X-Request-ID for request correlation
//   - Logs request start with method, path, client info
//   - Logs request completion with status, bytes, duration
//   - Adds request ID to response headers for client-side tracing
//   - Propagates request ID through context for downstream logging
//
// Log fields:
//   - request_id: Unique identifier for request tracing
//   - method: HTTP method (GET, POST, etc.)
//   - path: Request path
//   - remote_addr: Client IP address
//   - user_agent: Client User-Agent header
//   - status: HTTP response status code
//   - bytes: Response body size in bytes
//   - duration_ms: Request processing time in milliseconds
//
// Request ID flow:
//  1. Check for existing X-Request-ID header (from load balancer/proxy)
//  2. Generate new UUID if not present
//  3. Add to context for use by handlers and services
//  4. Include in response headers for client correlation
//
// Example logs:
//
//	{"level":"info","request_id":"abc-123","method":"GET","path":"/api/auth/me","msg":"Request started"}
//	{"level":"info","request_id":"abc-123","status":200,"bytes":156,"duration_ms":45,"msg":"Request completed"}
//
// Usage:
//
//	r.Use(middleware.Logger())
func Logger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Generate request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add request ID to context
			ctx := utils.WithRequestID(r.Context(), requestID)
			r = r.WithContext(ctx)

			// Create response writer wrapper to capture status code
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Add request ID to response headers
			ww.Header().Set("X-Request-ID", requestID)

			// Log request
			log.Info().
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Msg("Request started")

			// Call next handler
			next.ServeHTTP(ww, r)

			// Log response
			duration := time.Since(start)
			log.Info().
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration_ms", duration).
				Msg("Request completed")
		})
	}
}

// Recoverer recovers from panics and logs the error.
// Prevents the entire application from crashing when a handler panics.
// This is critical middleware that should be registered early in the chain.
//
// Behavior:
//  1. Catches any panic in downstream handlers
//  2. Logs the panic with error details and request context
//  3. Returns 500 Internal Server Error to the client
//  4. Prevents application crash
//
// The panic details are logged but NOT exposed to the client for security.
// Use centralized error logging/monitoring to track panics in production.
//
// Example panic log:
//
//	{
//	  "level": "error",
//	  "error": "runtime error: invalid memory address",
//	  "method": "POST",
//	  "path": "/api/users",
//	  "msg": "Panic recovered"
//	}
//
// Usage (should be early in middleware chain):
//
//	r.Use(middleware.Recoverer())
//	r.Use(middleware.Logger())
//	r.Use(middleware.JWTAuth(jwtService))
func Recoverer() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Error().
						Interface("error", err).
						Str("method", r.Method).
						Str("path", r.URL.Path).
						Msg("Panic recovered")

					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security-related HTTP headers to all responses.
// Implements security best practices to protect against common web vulnerabilities.
//
// Headers added:
//
//   - X-Content-Type-Options: nosniff
//     Prevents MIME type sniffing attacks
//
//   - X-Frame-Options: DENY
//     Prevents clickjacking by disallowing iframe embedding
//
//   - X-XSS-Protection: 1; mode=block
//     Enables browser XSS filter (legacy browsers)
//
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains
//     Forces HTTPS for 1 year including subdomains (HSTS)
//
//   - Content-Security-Policy: restrictive policy
//     Controls resource loading to prevent XSS
//     Allows: self resources, inline scripts/styles, Google profile images
//
//   - Referrer-Policy: strict-origin-when-cross-origin
//     Controls referrer information leakage
//
// Production considerations:
//   - HSTS preload: Consider adding to browser preload list
//   - CSP: Adjust policy based on actual resource needs
//   - Report-URI: Add CSP violation reporting endpoint
//
// Usage:
//
//	r.Use(middleware.SecurityHeaders())
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			// Allow inline scripts for the static frontend and images from Google
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://lh3.googleusercontent.com data:")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			next.ServeHTTP(w, r)
		})
	}
}
