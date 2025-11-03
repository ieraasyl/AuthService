// Package utils provides retry logic with exponential backoff for transient failures.
// It supports configurable retry policies, jitter to prevent thundering herd,
// and context-aware cancellation. Use this for resilient external service calls,
// database connections, and other operations that may experience temporary failures.
package utils

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"
)

// RetryFunc is a function that can be retried. It should return an error
// if the operation failed and nil on success.
type RetryFunc func() error

// RetryConfig holds configuration for retry behavior with exponential backoff.
type RetryConfig struct {
	MaxAttempts     int           // Maximum number of retry attempts (including first try)
	InitialDelay    time.Duration // Initial delay before first retry
	MaxDelay        time.Duration // Maximum delay between retries
	Multiplier      float64       // Exponential backoff multiplier
	Jitter          bool          // Add random jitter to delays
	RetryableErrors []error       // Specific errors that should trigger retry (nil = retry all)
}

// DefaultRetryConfig returns a retry configuration with sensible defaults.
// Use this for general-purpose retry logic.
//
// Configuration:
//   - Max attempts: 3
//   - Initial delay: 100ms
//   - Max delay: 5s
//   - Multiplier: 2.0 (exponential backoff)
//   - Jitter: enabled
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// DatabaseRetryConfig returns a retry configuration optimized for database operations.
// Database connections often have transient failures during startup or network blips.
//
// Configuration:
//   - Max attempts: 5
//   - Initial delay: 50ms
//   - Max delay: 2s
//   - Multiplier: 2.0
//   - Jitter: enabled
func DatabaseRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     2 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// ExternalAPIRetryConfig returns a retry configuration for external API calls.
// External APIs may have rate limits or temporary unavailability.
//
// Configuration:
//   - Max attempts: 3
//   - Initial delay: 500ms
//   - Max delay: 10s
//   - Multiplier: 2.0
//   - Jitter: enabled
func ExternalAPIRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// Retry executes a function with retry logic and exponential backoff.
// The function will be retried until it succeeds, max attempts is reached,
// or the context is cancelled.
//
// The delay between retries follows exponential backoff:
//
//	delay = initialDelay * multiplier^(attempt-1)
//
// Optional jitter adds random variance (±25%) to prevent thundering herd.
//
// Example:
//
//	ctx := context.Background()
//	config := utils.DatabaseRetryConfig()
//	err := utils.Retry(ctx, config, func() error {
//	    return db.Ping()
//	})
func Retry(ctx context.Context, config RetryConfig, fn RetryFunc) error {
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			// Success
			if attempt > 1 {
				log.Info().
					Int("attempt", attempt).
					Int("max_attempts", config.MaxAttempts).
					Msg("Operation succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryable(err, config.RetryableErrors) {
			log.Debug().
				Err(err).
				Int("attempt", attempt).
				Msg("Error is not retryable, aborting")
			return fmt.Errorf("non-retryable error: %w", err)
		}

		// Check if we've exhausted attempts
		if attempt >= config.MaxAttempts {
			log.Warn().
				Err(err).
				Int("attempts", attempt).
				Msg("Max retry attempts reached")
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, config)

		log.Debug().
			Err(err).
			Int("attempt", attempt).
			Int("max_attempts", config.MaxAttempts).
			Dur("delay", delay).
			Msg("Operation failed, retrying after delay")

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("max retries exceeded (%d attempts): %w", config.MaxAttempts, lastErr)
}

// RetryWithResult executes a function with retry logic and returns a result.
// Generic version of Retry that can return a value along with an error.
//
// Example:
//
//	ctx := context.Background()
//	config := utils.ExternalAPIRetryConfig()
//	data, err := utils.RetryWithResult(ctx, config, func() ([]byte, error) {
//	    return fetchDataFromAPI()
//	})
func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn func() (T, error)) (T, error) {
	var result T
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Execute the function
		res, err := fn()
		if err == nil {
			// Success
			if attempt > 1 {
				log.Info().
					Int("attempt", attempt).
					Int("max_attempts", config.MaxAttempts).
					Msg("Operation succeeded after retry")
			}
			return res, nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryable(err, config.RetryableErrors) {
			log.Debug().
				Err(err).
				Int("attempt", attempt).
				Msg("Error is not retryable, aborting")
			return result, fmt.Errorf("non-retryable error: %w", err)
		}

		// Check if we've exhausted attempts
		if attempt >= config.MaxAttempts {
			log.Warn().
				Err(err).
				Int("attempts", attempt).
				Msg("Max retry attempts reached")
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, config)

		log.Debug().
			Err(err).
			Int("attempt", attempt).
			Int("max_attempts", config.MaxAttempts).
			Dur("delay", delay).
			Msg("Operation failed, retrying after delay")

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return result, fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return result, fmt.Errorf("max retries exceeded (%d attempts): %w", config.MaxAttempts, lastErr)
}

// calculateDelay calculates the delay before next retry using exponential backoff.
// The formula is: initialDelay * multiplier^(attempt-1), capped at maxDelay.
// Optional jitter adds ±25% random variance to the delay.
func calculateDelay(attempt int, config RetryConfig) time.Duration {
	// Calculate exponential backoff: initialDelay * multiplier^(attempt-1)
	delay := float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt-1))

	// Cap at max delay
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}

	// Add jitter if enabled (random variance of ±25%)
	if config.Jitter {
		jitterRange := delay * 0.25
		jitter := (rand.Float64() * 2 * jitterRange) - jitterRange
		delay += jitter
	}

	return time.Duration(delay)
}

// isRetryable checks if an error should trigger a retry.
// If no specific retryable errors are configured, all errors are retryable.
func isRetryable(err error, retryableErrors []error) bool {
	// If no specific retryable errors defined, retry all errors
	if len(retryableErrors) == 0 {
		return true
	}

	// Check if error matches any retryable error
	for _, retryableErr := range retryableErrors {
		if err == retryableErr || err.Error() == retryableErr.Error() {
			return true
		}
	}

	return false
}

// RetryableError wraps an error to explicitly mark it as retryable.
// Useful when you want fine-grained control over which errors should trigger retries.
type RetryableError struct {
	Err error
}

func (e *RetryableError) Error() string {
	return e.Err.Error()
}

func (e *RetryableError) Unwrap() error {
	return e.Err
}

// NewRetryableError creates a new retryable error wrapper.
//
// Example:
//
//	if isTransientError(err) {
//	    return utils.NewRetryableError(err)
//	}
func NewRetryableError(err error) error {
	return &RetryableError{Err: err}
}

// IsRetryableError checks if an error is marked as retryable.
func IsRetryableError(err error) bool {
	_, ok := err.(*RetryableError)
	return ok
}

// Simple retry helpers for common use cases

// RetrySimple executes a function with default retry configuration.
// Convenient shorthand for common retry scenarios.
func RetrySimple(ctx context.Context, fn RetryFunc) error {
	return Retry(ctx, DefaultRetryConfig(), fn)
}

// RetryDatabase executes a database operation with retry logic.
// Uses database-optimized retry configuration (5 attempts, shorter delays).
func RetryDatabase(ctx context.Context, fn RetryFunc) error {
	return Retry(ctx, DatabaseRetryConfig(), fn)
}

// RetryExternalAPI executes an external API call with retry logic.
// Uses API-optimized retry configuration (longer delays, 3 attempts).
func RetryExternalAPI(ctx context.Context, fn RetryFunc) error {
	return Retry(ctx, ExternalAPIRetryConfig(), fn)
}

// RetryN executes a function with a custom number of retry attempts.
// Uses default configuration with only the max attempts changed.
func RetryN(ctx context.Context, maxAttempts int, fn RetryFunc) error {
	config := DefaultRetryConfig()
	config.MaxAttempts = maxAttempts
	return Retry(ctx, config, fn)
}

// RetryWithTimeout executes a function with retry and an overall timeout.
// The operation will stop retrying when the timeout is reached, even if
// max attempts has not been exhausted.
//
// Example:
//
//	err := utils.RetryWithTimeout(5*time.Second, config, func() error {
//	    return performOperation()
//	})
func RetryWithTimeout(timeout time.Duration, config RetryConfig, fn RetryFunc) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Retry(ctx, config, fn)
}

// RetryWithCallback executes a function with retry and calls a callback on each failure.
// The callback receives the attempt number and error, useful for logging or metrics.
//
// Example:
//
//	err := utils.RetryWithCallback(ctx, config, fn, func(attempt int, err error) {
//	    log.Warn().Int("attempt", attempt).Err(err).Msg("Retry failed")
//	    metrics.IncrementRetryCounter()
//	})
func RetryWithCallback(ctx context.Context, config RetryConfig, fn RetryFunc, onRetry func(attempt int, err error)) error {
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if !isRetryable(err, config.RetryableErrors) {
			return fmt.Errorf("non-retryable error: %w", err)
		}

		if attempt >= config.MaxAttempts {
			break
		}

		// Call callback
		if onRetry != nil {
			onRetry(attempt, err)
		}

		delay := calculateDelay(attempt, config)

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("max retries exceeded (%d attempts): %w", config.MaxAttempts, lastErr)
}
