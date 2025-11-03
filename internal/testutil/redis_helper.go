package testutil

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/redis/go-redis/v9"
)

// SetupMiniRedis creates a miniredis instance for testing
// Returns the miniredis server and a cleanup function
func SetupMiniRedis(t *testing.T) (*miniredis.Miniredis, func()) {
	t.Helper()

	mr := miniredis.RunT(t)

	cleanup := func() {
		mr.Close()
	}

	return mr, cleanup
}

// NewTestRedisDB creates a RedisDB connected to miniredis for testing
func NewTestRedisDB(t *testing.T, mr *miniredis.Miniredis) *database.RedisDB {
	t.Helper()

	cfg := &config.RedisConfig{
		Host:     mr.Host(),
		Port:     mr.Port(),
		Password: "",
		DB:       0,
	}

	db, err := database.NewRedisDB(cfg)
	if err != nil {
		t.Fatalf("Failed to create test Redis DB: %v", err)
	}

	return db
}

// NewTestRedisClient creates a Redis client connected to miniredis
func NewTestRedisClient(t *testing.T, mr *miniredis.Miniredis) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
		DB:   0,
	})

	return client
}

// FlushRedis clears all data from miniredis
func FlushRedis(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	mr.FlushAll()
}
