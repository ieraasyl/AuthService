// Package cache provides a generic Redis-based caching layer with JSON serialization.
// It offers a high-level API for caching arbitrary Go structs with automatic
// marshaling/unmarshaling, pattern-based deletion, and cache-aside pattern support.
//
// Features:
//   - Automatic JSON serialization/deserialization
//   - TTL-based expiration
//   - Pattern-based key deletion using SCAN
//   - GetOrSet for cache-aside pattern
//   - Atomic operations (SetNX, Increment)
//   - Distributed lock primitives
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Cache provides a generic caching interface with JSON serialization.
// All operations use JSON for serialization, making it easy to cache any Go struct.
type Cache struct {
	client *redis.Client
}

// NewCache creates a new cache instance wrapping a Redis client.
// The client should be configured with appropriate connection pool settings.
//
// Example:
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr: "localhost:6379",
//	})
//	cache := cache.NewCache(redisClient)
func NewCache(client *redis.Client) *Cache {
	return &Cache{
		client: client,
	}
}

// Get retrieves a value from cache and unmarshals it into the target.
// Returns ErrCacheMiss if the key doesn't exist.
//
// The target must be a pointer to the type you want to unmarshal into.
//
// Example:
//
//	var user models.User
//	err := cache.Get(ctx, cache.UserKey(userID), &user)
//	if err == cache.ErrCacheMiss {
//	    // Key not found, load from database
//	} else if err != nil {
//	    // Other error
//	}
func (c *Cache) Get(ctx context.Context, key string, target interface{}) error {
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		log.Error().Err(err).Str("key", key).Msg("Failed to get from cache")
		return fmt.Errorf("cache get error: %w", err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to unmarshal cached data")
		return fmt.Errorf("unmarshal error: %w", err)
	}

	return nil
}

// Set stores a value in cache with the specified TTL.
// The value is automatically marshaled to JSON.
//
// Example:
//
//	user := &models.User{ID: uuid.New(), Email: "user@example.com"}
//	err := cache.Set(ctx, cache.UserKey(user.ID), user, 15*time.Minute)
func (c *Cache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to marshal data for cache")
		return fmt.Errorf("marshal error: %w", err)
	}

	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to set cache")
		return fmt.Errorf("cache set error: %w", err)
	}

	log.Debug().Str("key", key).Dur("ttl", ttl).Msg("Cached data")
	return nil
}

// Delete removes one or more keys from cache.
// This operation is atomic - either all keys are deleted or none are.
//
// Example:
//
//	cache.Delete(ctx, cache.UserKey(userID), cache.UserByEmailKey(email))
func (c *Cache) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		log.Error().Err(err).Strs("keys", keys).Msg("Failed to delete from cache")
		return fmt.Errorf("cache delete error: %w", err)
	}

	log.Debug().Strs("keys", keys).Msg("Deleted from cache")
	return nil
}

// DeletePattern removes all keys matching a pattern using SCAN.
// This is safe for production use (unlike KEYS command) as it uses cursor iteration.
//
// Pattern syntax follows Redis glob-style patterns:
//   - * matches any characters
//   - ? matches a single character
//   - [abc] matches a, b, or c
//
// Example:
//
//	// Delete all user cache entries
//	cache.DeletePattern(ctx, "user:*")
//
//	// Delete all session cache for a specific user
//	cache.DeletePattern(ctx, fmt.Sprintf("session:%s:*", userID))
func (c *Cache) DeletePattern(ctx context.Context, pattern string) error {
	var cursor uint64
	var deletedCount int

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			log.Error().Err(err).Str("pattern", pattern).Msg("Failed to scan cache keys")
			return fmt.Errorf("cache scan error: %w", err)
		}

		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				log.Error().Err(err).Str("pattern", pattern).Msg("Failed to delete keys")
				return fmt.Errorf("cache delete error: %w", err)
			}
			deletedCount += len(keys)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	log.Debug().Str("pattern", pattern).Int("count", deletedCount).Msg("Deleted keys by pattern")
	return nil
}

// Exists checks if a key exists in cache without retrieving its value.
// More efficient than Get when you only need to check existence.
//
// Example:
//
//	exists, err := cache.Exists(ctx, cache.TokenKey(token))
//	if exists {
//	    return errors.New("token already blacklisted")
//	}
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to check cache existence")
		return false, fmt.Errorf("cache exists error: %w", err)
	}
	return count > 0, nil
}

// GetOrSet implements the cache-aside pattern.
// It attempts to get from cache, and on miss, executes the loader function
// and caches the result. This is useful for expensive operations like database queries.
//
// The loader function should return the data to cache. If the loader returns an error,
// nothing is cached and the error is returned.
//
// Example:
//
//	var user models.User
//	err := cache.GetOrSet(ctx, cache.UserKey(userID), 15*time.Minute, &user, func() (interface{}, error) {
//	    return db.GetUserByID(ctx, userID)
//	})
func (c *Cache) GetOrSet(ctx context.Context, key string, ttl time.Duration, target interface{}, loader func() (interface{}, error)) error {
	// Try to get from cache first
	err := c.Get(ctx, key, target)
	if err == nil {
		log.Debug().Str("key", key).Msg("Cache hit")
		return nil
	}

	// If not a cache miss, return the error
	if err != ErrCacheMiss {
		return err
	}

	log.Debug().Str("key", key).Msg("Cache miss, loading data")

	// Load the data
	data, err := loader()
	if err != nil {
		return fmt.Errorf("loader error: %w", err)
	}

	// Cache the loaded data
	if err := c.Set(ctx, key, data, ttl); err != nil {
		// Log but don't fail - we have the data
		log.Warn().Err(err).Str("key", key).Msg("Failed to cache loaded data")
	}

	// Marshal and unmarshal to populate target
	// This ensures type consistency
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	if err := json.Unmarshal(bytes, target); err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	return nil
}

// SetNX sets a key only if it doesn't exist (SET if Not eXists).
// Returns true if the key was set, false if it already existed.
//
// This is useful for implementing distributed locks or ensuring idempotency.
//
// Example:
//
//	// Distributed lock
//	lockKey := fmt.Sprintf("lock:user:%s", userID)
//	acquired, err := cache.SetNX(ctx, lockKey, "locked", 30*time.Second)
//	if !acquired {
//	    return errors.New("operation already in progress")
//	}
//	defer cache.Delete(ctx, lockKey)
func (c *Cache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("marshal error: %w", err)
	}

	ok, err := c.client.SetNX(ctx, key, data, ttl).Result()
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to set if not exists")
		return false, fmt.Errorf("cache setnx error: %w", err)
	}

	return ok, nil
}

// Increment atomically increments a counter by delta.
// Returns the new value after increment. If the key doesn't exist, it's created.
//
// Example:
//
//	// Increment API call counter
//	count, err := cache.Increment(ctx, fmt.Sprintf("api:calls:%s", userID), 1)
//	if count > 1000 {
//	    return errors.New("rate limit exceeded")
//	}
func (c *Cache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	val, err := c.client.IncrBy(ctx, key, delta).Result()
	if err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to increment counter")
		return 0, fmt.Errorf("cache increment error: %w", err)
	}
	return val, nil
}

// Expire sets or updates the TTL on an existing key.
// If the key doesn't exist, this operation has no effect.
//
// Example:
//
//	// Extend cache lifetime for active users
//	cache.Expire(ctx, cache.UserKey(userID), 30*time.Minute)
func (c *Cache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if err := c.client.Expire(ctx, key, ttl).Err(); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to set expiration")
		return fmt.Errorf("cache expire error: %w", err)
	}
	return nil
}
