package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: These tests focus on response structure and HTTP behavior.
// Full integration tests with real PostgreSQL/Redis connections would require
// testcontainers or docker-compose. For unit tests, we verify the handler logic.

func TestHealth(t *testing.T) {
	t.Run("returns 200 OK with correct structure", func(t *testing.T) {
		// Setup - using nil databases since Health() doesn't check them
		handler := &HealthHandler{
			postgres: nil,
			redis:    nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		// Execute
		handler.Health(rec, req)

		// Assert HTTP status
		assert.Equal(t, http.StatusOK, rec.Code)

		// Assert response structure
		var response HealthResponse
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response.Status)
		assert.False(t, response.Timestamp.IsZero())
		assert.Nil(t, response.Services) // Health doesn't check services
	})

	t.Run("includes correct content-type header", func(t *testing.T) {
		handler := &HealthHandler{}
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.Health(rec, req)

		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	})
}

func TestReady(t *testing.T) {
	// Note: Ready() tests require real or mocked database connections.
	// Since HealthHandler uses concrete types (*database.PostgresDB, *database.RedisDB),
	// we'd need dependency injection with interfaces for proper unit testing.
	// These tests are integration tests that require actual database connections
	// or testcontainers. Skipping for now.

	t.Skip("Ready() requires database connections - use integration tests with testcontainers")

	// TODO: Implement with testcontainers or database interfaces
	// Example structure:
	//
	// t.Run("all services healthy returns 200 OK", func(t *testing.T) {
	//     // Setup testcontainers for PostgreSQL and Redis
	//     pg := setupTestPostgres(t)
	//     rd := setupTestRedis(t)
	//     handler := NewHealthHandler(pg, rd)
	//
	//     req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	//     rec := httptest.NewRecorder()
	//
	//     handler.Ready(rec, req)
	//
	//     assert.Equal(t, http.StatusOK, rec.Code)
	//     assert.Contains(t, rec.Body.String(), `"status":"ok"`)
	// })
}

func TestHealthResponse_JSONSerialization(t *testing.T) {
	t.Run("serializes all fields correctly", func(t *testing.T) {
		handler := &HealthHandler{}
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.Health(rec, req)

		var response map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response["status"])
		assert.NotNil(t, response["timestamp"])
	})
}

// Benchmark health endpoint
func BenchmarkHealth(b *testing.B) {
	handler := &HealthHandler{}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.Health(rec, req)
	}
}

// TODO: Add integration tests with testcontainers or docker-compose
// to verify Ready() behavior with real PostgreSQL and Redis instances.
//
// Example integration test structure:
// func TestReady_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("Skipping integration test")
//     }
//
//     // Setup testcontainers for PostgreSQL and Redis
//     // Create handler with real connections
//     // Test healthy and unhealthy scenarios
// }
