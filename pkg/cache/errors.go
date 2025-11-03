// Package cache defines common error types used throughout the caching layer.
package cache

import "errors"

// Common cache errors
var (
	// ErrCacheMiss indicates the requested key was not found in cache.
	// This is not necessarily an error condition - it's expected behavior
	// when a key hasn't been cached yet or has expired.
	//
	// Example usage:
	//
	//	err := cache.Get(ctx, key, &data)
	//	if err == cache.ErrCacheMiss {
	//	    // Load from database
	//	} else if err != nil {
	//	    // Handle other errors
	//	}
	ErrCacheMiss = errors.New("cache miss")

	// ErrCacheInvalidation indicates cache invalidation failed.
	// This typically occurs when attempting to delete keys that don't exist
	// or when there's a connection issue with Redis.
	ErrCacheInvalidation = errors.New("cache invalidation failed")
)
