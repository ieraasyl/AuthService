package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics for comprehensive application monitoring.
// All metrics are registered in the default Prometheus registry and
// exposed via the /metrics endpoint.

var (
	// httpRequestsTotal counts all HTTP requests by method, path, and status.
	// Use for request rate monitoring and error rate calculation.
	//
	// Labels: method (GET, POST, etc.), path (/api/auth/login), status (200, 404, 500)
	// Type: Counter
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// httpRequestDuration measures request processing time for performance monitoring.
	// Use for latency analysis and SLO tracking (P50, P95, P99).
	//
	// Labels: method, path
	// Type: Histogram
	// Buckets: Default Prometheus buckets (0.005s to 10s)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// httpRequestSize tracks request body sizes for bandwidth and quota monitoring.
	//
	// Labels: method, path
	// Type: Histogram
	// Buckets: Exponential from 100 bytes to 100 MB
	httpRequestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	// httpResponseSize tracks response body sizes for bandwidth monitoring.
	//
	// Labels: method, path
	// Type: Histogram
	// Buckets: Exponential from 100 bytes to 100 MB
	httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	// activeSessions tracks the current number of active user sessions.
	// Use for capacity planning and user activity monitoring.
	//
	// Type: Gauge (can go up or down)
	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_active_sessions",
			Help: "Number of active user sessions",
		},
	)

	// authAttemptsTotal counts authentication attempts by result (success/failure).
	// Use for security monitoring and fraud detection.
	//
	// Labels: result (success, invalid_credentials, invalid_state, etc.)
	// Type: Counter
	authAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"result"},
	)

	// tokenRefreshTotal counts token refresh attempts by result.
	// Use for monitoring token rotation and detecting refresh abuse.
	//
	// Labels: result (success, invalid_token, expired, etc.)
	// Type: Counter
	tokenRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_token_refresh_total",
			Help: "Total number of token refresh attempts",
		},
		[]string{"result"},
	)

	// dbQueriesTotal counts database queries by database, operation, and status.
	// Use for query rate monitoring and error tracking.
	//
	// Labels: database (postgres, redis), operation (SELECT, INSERT, GET, SET), status (success, error)
	// Type: Counter
	dbQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"database", "operation", "status"},
	)

	// dbQueryDuration measures database query execution time.
	// Use for identifying slow queries and database performance issues.
	//
	// Labels: database (postgres, redis), operation (SELECT, INSERT, GET, SET)
	// Type: Histogram
	// Buckets: Default Prometheus buckets
	dbQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"database", "operation"},
	)
)

// init registers all metrics with the Prometheus default registry.
// This is called automatically when the package is imported.
// Panics if any metric name conflicts with existing registrations.
func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(httpRequestSize)
	prometheus.MustRegister(httpResponseSize)
	prometheus.MustRegister(activeSessions)
	prometheus.MustRegister(authAttemptsTotal)
	prometheus.MustRegister(tokenRefreshTotal)
	prometheus.MustRegister(dbQueriesTotal)
	prometheus.MustRegister(dbQueryDuration)
}

// Metrics creates middleware for collecting HTTP metrics.
// Records request count, duration, request size, and response size
// for every HTTP request that passes through.
//
// Metrics collected per request:
//   - Request count (labeled by method, path, status)
//   - Request duration (labeled by method, path)
//   - Request size if Content-Length > 0 (labeled by method, path)
//   - Response size (labeled by method, path)
//
// The middleware wraps the response writer to capture status code
// and bytes written, which are not normally accessible.
//
// Performance impact: Negligible (<1ms per request overhead)
//
// Example Prometheus queries:
//
//	# Request rate by endpoint
//	rate(http_requests_total[5m])
//
//	# Error rate percentage
//	sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
//
//	# P95 latency
//	histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
//
// Usage:
//
//	r.Use(middleware.Metrics())
func Metrics() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status and size
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Record request size
			requestSize := float64(r.ContentLength)
			if requestSize > 0 {
				httpRequestSize.WithLabelValues(r.Method, r.URL.Path).Observe(requestSize)
			}

			// Process request
			next.ServeHTTP(ww, r)

			// Record metrics
			duration := time.Since(start).Seconds()
			status := strconv.Itoa(ww.Status())

			httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, status).Inc()
			httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
			httpResponseSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(ww.BytesWritten()))
		})
	}
}

// MetricsHandler returns the Prometheus metrics HTTP handler.
// Exposes all registered metrics in Prometheus text format for scraping.
//
// This endpoint should be exposed on a separate port or protected path
// for security. Never expose it publicly without authentication.
//
// Response format: Prometheus text-based exposition format
//
// Example metrics output:
//
//	# HELP http_requests_total Total number of HTTP requests
//	# TYPE http_requests_total counter
//	http_requests_total{method="GET",path="/api/auth/me",status="200"} 1234
//	http_requests_total{method="POST",path="/api/auth/login",status="200"} 567
//
// Usage:
//
//	r.Get("/metrics", middleware.MetricsHandler().ServeHTTP)
//
// Prometheus scrape config:
//
//	scrape_configs:
//	  - job_name: 'myapp'
//	    static_configs:
//	      - targets: ['localhost:8080']
//	    metrics_path: '/metrics'
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// IncrementAuthAttempts increments the authentication attempts counter.
// Call this in authentication handlers to track login success and failure rates.
//
// Parameters:
//   - result: Outcome of the attempt (e.g., "success", "invalid_credentials", "invalid_state")
//
// Example:
//
//	// In OAuth callback handler
//	if err != nil {
//	    middleware.IncrementAuthAttempts("oauth_failed")
//	    return
//	}
//	middleware.IncrementAuthAttempts("success")
func IncrementAuthAttempts(result string) {
	authAttemptsTotal.WithLabelValues(result).Inc()
}

// IncrementTokenRefresh increments the token refresh counter.
// Call this in token refresh handlers to monitor refresh patterns and abuse.
//
// Parameters:
//   - result: Outcome of the refresh (e.g., "success", "invalid_token", "expired")
//
// Example:
//
//	tokens, err := jwtService.RefreshAccessToken(ctx, refreshToken)
//	if err != nil {
//	    middleware.IncrementTokenRefresh("invalid_token")
//	    return
//	}
//	middleware.IncrementTokenRefresh("success")
func IncrementTokenRefresh(result string) {
	tokenRefreshTotal.WithLabelValues(result).Inc()
}

// SetActiveSessions sets the active sessions gauge to the specified value.
// Call this periodically (e.g., every minute) to update the active session count.
//
// This should be updated by a background job that queries Redis for
// the current number of active sessions.
//
// Parameters:
//   - count: Current number of active sessions
//
// Example background job:
//
//	func updateSessionMetrics(ctx context.Context, redis *RedisDB) {
//	    ticker := time.NewTicker(1 * time.Minute)
//	    for range ticker.C {
//	        count, err := redis.CountActiveSessions(ctx)
//	        if err == nil {
//	            middleware.SetActiveSessions(float64(count))
//	        }
//	    }
//	}
func SetActiveSessions(count float64) {
	activeSessions.Set(count)
}

// RecordDBQuery records database query metrics including count and duration.
// Call this after every database operation to track query performance and errors.
//
// Parameters:
//   - database: Database type ("postgres" or "redis")
//   - operation: Operation type (e.g., "SELECT", "INSERT", "GET", "SET", "SCAN")
//   - status: Result status ("success" or "error")
//   - duration: How long the query took to execute
//
// This function records both the query count (counter) and duration (histogram),
// enabling analysis of both query rate and performance.
//
// Example:
//
//	start := time.Now()
//	user, err := db.GetUserByID(ctx, userID)
//	duration := time.Since(start)
//
//	if err != nil {
//	    middleware.RecordDBQuery("postgres", "SELECT", "error", duration)
//	} else {
//	    middleware.RecordDBQuery("postgres", "SELECT", "success", duration)
//	}
func RecordDBQuery(database, operation, status string, duration time.Duration) {
	dbQueriesTotal.WithLabelValues(database, operation, status).Inc()
	dbQueryDuration.WithLabelValues(database, operation).Observe(duration.Seconds())
}
