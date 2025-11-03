// Package handlers provides HTTP request handlers for the API endpoints.
// Handlers coordinate between the HTTP layer and service layer, handling
// request parsing, validation, and response formatting.
//
// This package includes handlers for:
//   - Health checks and readiness probes
//   - Authentication flows (OAuth, login, logout)
//   - User management
//   - Session management
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/rs/zerolog/log"
)

// HealthHandler handles health check endpoints for monitoring and orchestration.
// Provides both simple liveness checks and detailed readiness checks that verify
// connectivity to dependent services (PostgreSQL and Redis).
type HealthHandler struct {
	postgres *database.PostgresDB // PostgreSQL connection for health checks
	redis    *database.RedisDB    // Redis connection for health checks
}

// NewHealthHandler creates a new health handler with database dependencies.
//
// Parameters:
//   - postgres: PostgreSQL database connection
//   - redis: Redis database connection
//
// Example:
//
//	healthHandler := handlers.NewHealthHandler(postgresDB, redisDB)
//	r.Get("/health", healthHandler.Health)
//	r.Get("/ready", healthHandler.Ready)
func NewHealthHandler(postgres *database.PostgresDB, redis *database.RedisDB) *HealthHandler {
	return &HealthHandler{
		postgres: postgres,
		redis:    redis,
	}
}

// HealthResponse represents the health check response structure.
// Used by both the basic health check and detailed readiness check.
//
// JSON example:
//
//	{
//	  "status": "ok",
//	  "timestamp": "2024-01-20T14:30:00Z",
//	  "services": {
//	    "postgres": "healthy",
//	    "redis": "healthy"
//	  }
//	}
type HealthResponse struct {
	Status    string            `json:"status"`             // Overall status: "ok" or "degraded"
	Timestamp time.Time         `json:"timestamp"`          // Current server time
	Services  map[string]string `json:"services,omitempty"` // Individual service health (readiness only)
}

// Health returns a simple health check indicating the service is running.
// This is a liveness probe - it only checks if the application is alive,
// not if it's ready to serve traffic. Use Ready() for readiness checks.
//
// Always returns 200 OK with {"status": "ok"} unless the application
// is completely non-functional.
//
// Kubernetes liveness probe example:
//
//	livenessProbe:
//	  httpGet:
//	    path: /health
//	    port: 8080
//	  initialDelaySeconds: 10
//	  periodSeconds: 30
//
// @Summary      Health check (liveness probe)
// @Description  Returns 200 OK if the service is running. Does not check dependencies.
// @Tags         health
// @Produce      json
// @Success      200  {object}  HealthResponse  "Service is alive"
// @Router       /health [get]
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now(),
	}

	utils.RespondWithJSON(w, r, http.StatusOK, response)
}

// Ready checks if the service is ready to accept traffic.
// This is a readiness probe that verifies connectivity to all dependent
// services (PostgreSQL and Redis). Returns 200 OK if all dependencies are
// healthy, or 503 Service Unavailable if any are down.
//
// Used by load balancers and orchestrators to determine if traffic should
// be routed to this instance. If this check fails, the instance is removed
// from the load balancer pool until it recovers.
//
// Health checks have a 5-second timeout to prevent hanging probes.
//
// Response status:
//   - "ok": All services healthy (200 OK)
//   - "degraded": One or more services unhealthy (503 Service Unavailable)
//
// Kubernetes readiness probe example:
//
//	readinessProbe:
//	  httpGet:
//	    path: /ready
//	    port: 8080
//	  initialDelaySeconds: 5
//	  periodSeconds: 10
//	  failureThreshold: 3
//
// @Summary      Readiness check
// @Description  Checks if the service and all dependencies (PostgreSQL, Redis) are healthy
// @Tags         health
// @Produce      json
// @Success      200  {object}  HealthResponse  "All services healthy"
// @Failure      503  {object}  HealthResponse  "One or more services unhealthy"
// @Router       /ready [get]
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	services := make(map[string]string)
	allHealthy := true

	// Check PostgreSQL
	if err := h.postgres.Ping(ctx); err != nil {
		log.Error().Err(err).Msg("PostgreSQL health check failed")
		services["postgres"] = "unhealthy"
		allHealthy = false
	} else {
		services["postgres"] = "healthy"
	}

	// Check Redis
	if err := h.redis.Ping(ctx); err != nil {
		log.Error().Err(err).Msg("Redis health check failed")
		services["redis"] = "unhealthy"
		allHealthy = false
	} else {
		services["redis"] = "healthy"
	}

	response := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now(),
		Services:  services,
	}

	statusCode := http.StatusOK
	if !allHealthy {
		response.Status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	utils.RespondWithJSON(w, r, statusCode, response)
}
