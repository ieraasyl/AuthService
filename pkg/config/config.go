// Package config provides application configuration management with environment
// variable loading, validation, and sensible defaults. It supports .env files
// for local development and validates all required settings on startup to
// prevent runtime configuration errors.
//
// Configuration is loaded from environment variables with the Load() function,
// which returns a validated Config struct or an error if required variables
// are missing or invalid.
//
// Example usage:
//
//	cfg, err := config.Load()
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Failed to load configuration")
//	}
//
//	// Use configuration
//	server := &http.Server{
//	    Addr: ":" + cfg.Server.Port,
//	}
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application.
// It aggregates all configuration sections into a single struct
// for easy access throughout the application.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	OAuth     OAuthConfig
	JWT       JWTConfig
	CORS      CORSConfig
	RateLimit RateLimitConfig
	Cache     CacheConfig
}

// ServerConfig holds server-specific configuration including port,
// environment, and external URLs.
type ServerConfig struct {
	Port        string
	Environment string
	FrontendURL string // URL to redirect after successful authentication
}

// DatabaseConfig holds PostgreSQL database configuration including
// connection parameters and pool settings.
type DatabaseConfig struct {
	Host     string
	Port     string
	Database string
	User     string
	Password string
	MaxConns int // Maximum number of connections in the pool
}

// RedisConfig holds Redis configuration including connection parameters,
// authentication, database selection, and pool size.
type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
	PoolSize int // Connection pool size
}

// OAuthConfig holds Google OAuth 2.0 configuration including client
// credentials and endpoint URLs.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserInfoURL  string // Google user info endpoint URL
}

// JWTConfig holds JWT token configuration including the signing secret
// and token expiration durations.
type JWTConfig struct {
	Secret        []byte
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration // Refresh token lifetime (default: 7 days)
}

// CORSConfig holds Cross-Origin Resource Sharing (CORS) configuration
// to control which origins can access the API.
type CORSConfig struct {
	AllowedOrigins []string // List of allowed origin URLs
}

// RateLimitConfig holds rate limiting configuration to protect against
// abuse and ensure fair resource usage.
type RateLimitConfig struct {
	RequestsPerMinute int
	WindowDuration    time.Duration // Time window for rate limiting (default: 1 minute)
}

// CacheConfig holds cache configuration including TTL values for different
// data types and cache enablement flag.
type CacheConfig struct {
	UserTTL    time.Duration
	SessionTTL time.Duration
	Enabled    bool // Master switch to enable/disable caching
}

// Load reads and validates configuration from environment variables.
// It attempts to load a .env file if present (for local development) but
// doesn't fail if the file is missing (for production deployments).
//
// Required environment variables:
//   - POSTGRES_PASSWORD: Database password
//   - GOOGLE_CLIENT_ID: Google OAuth client ID
//   - GOOGLE_CLIENT_SECRET: Google OAuth client secret
//   - JWT_SECRET: Secret for JWT signing (≥32 bytes)
//
// Optional environment variables have sensible defaults. See .env.example
// for a complete list.
//
// Returns an error if any required variable is missing or if validation fails.
//
// Example:
//
//	cfg, err := config.Load()
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Configuration error")
//	}
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error in production)
	_ = godotenv.Load()

	// Get required environment variables with error handling
	postgresPassword, err := getEnvRequired("POSTGRES_PASSWORD")
	if err != nil {
		return nil, err
	}

	googleClientID, err := getEnvRequired("GOOGLE_CLIENT_ID")
	if err != nil {
		return nil, err
	}

	googleClientSecret, err := getEnvRequired("GOOGLE_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	jwtSecret, err := getEnvRequired("JWT_SECRET")
	if err != nil {
		return nil, err
	}

	config := &Config{
		Server: ServerConfig{
			Port:        getEnv("PORT", "8080"),
			Environment: getEnv("ENV", "development"),
			FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnv("POSTGRES_PORT", "5432"),
			Database: getEnv("POSTGRES_DB", "authdb"),
			User:     getEnv("POSTGRES_USER", "authuser"),
			Password: postgresPassword,
			MaxConns: getEnvAsInt("POSTGRES_MAX_CONNS", 25),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
			PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 100),
		},
		OAuth: OAuthConfig{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			RedirectURL:  getEnv("AUTH_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
			UserInfoURL:  getEnv("GOOGLE_USER_INFO", "https://www.googleapis.com/oauth2/v2/userinfo"),
		},
		JWT: JWTConfig{
			Secret:        []byte(jwtSecret),
			AccessExpiry:  getEnvAsDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshExpiry: getEnvAsDuration("JWT_REFRESH_EXPIRY", 168*time.Hour), // 7 days
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvAsSlice("ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		},
		RateLimit: RateLimitConfig{
			RequestsPerMinute: getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
			WindowDuration:    getEnvAsDuration("RATE_LIMIT_WINDOW", 1*time.Minute),
		},
		Cache: CacheConfig{
			UserTTL:    getEnvAsDuration("CACHE_USER_TTL", 15*time.Minute),
			SessionTTL: getEnvAsDuration("CACHE_SESSION_TTL", 5*time.Minute),
			Enabled:    getEnv("CACHE_ENABLED", "true") == "true",
		},
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate checks if all required configuration is present and valid.
// It performs comprehensive validation including:
//   - Port numbers are valid integers
//   - URLs are properly formatted
//   - JWT secret meets minimum length requirement (32 bytes)
//   - Required credentials are present
//
// This method is called automatically by Load() but can also be called
// independently for testing or validation purposes.
//
// Returns an error describing the first validation failure encountered,
// or nil if all configuration is valid.
func (c *Config) Validate() error {
	// Validate server port
	if c.Server.Port == "" {
		return fmt.Errorf("server port is required")
	}
	if _, err := strconv.Atoi(c.Server.Port); err != nil {
		return fmt.Errorf("server port must be a valid integer: %w", err)
	}

	// Validate database port
	if _, err := strconv.Atoi(c.Database.Port); err != nil {
		return fmt.Errorf("database port must be a valid integer: %w", err)
	}

	// Validate Redis port
	if _, err := strconv.Atoi(c.Redis.Port); err != nil {
		return fmt.Errorf("redis port must be a valid integer: %w", err)
	}

	// Validate OAuth configuration
	if c.OAuth.ClientID == "" {
		return fmt.Errorf("google OAuth client ID is required")
	}
	if c.OAuth.ClientSecret == "" {
		return fmt.Errorf("google OAuth client secret is required")
	}

	// Validate redirect URL format
	if _, err := url.ParseRequestURI(c.OAuth.RedirectURL); err != nil {
		return fmt.Errorf("invalid OAuth redirect URL: %w", err)
	}

	// Validate user info URL format
	if _, err := url.ParseRequestURI(c.OAuth.UserInfoURL); err != nil {
		return fmt.Errorf("invalid OAuth user info URL: %w", err)
	}

	// Validate frontend URL format
	if _, err := url.ParseRequestURI(c.Server.FrontendURL); err != nil {
		return fmt.Errorf("invalid frontend URL: %w", err)
	}

	// Validate JWT secret
	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 bytes")
	}

	// Validate database password
	if c.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}

	return nil
}

// DSN returns the PostgreSQL Data Source Name (connection string) formatted
// for use with the lib/pq driver.
//
// Format: "host=X port=Y user=Z password=W dbname=N sslmode=disable"
//
// Note: SSL is disabled for local development. In production, consider
// enabling SSL and configuring appropriate certificates.
//
// Example:
//
//	db, err := sql.Open("postgres", cfg.Database.DSN())
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.User, c.Password, c.Database,
	)
}

// Address returns the Redis server address in "host:port" format.
//
// Example:
//
//	client := redis.NewClient(&redis.Options{
//	    Addr: cfg.Redis.Address(),
//	})
func (c *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

// Helper functions for environment variable parsing

// getEnv retrieves an environment variable with a default fallback.
// Returns the environment variable value if set, otherwise returns defaultValue.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvRequired retrieves a required environment variable.
// Returns an error if the variable is not set or is empty.
//
// Use this for configuration that has no sensible default and must be
// explicitly provided by the operator.
func getEnvRequired(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return value, nil
}

// getEnvAsInt retrieves an environment variable as an integer with a default fallback.
// If the variable is not set or cannot be parsed as an integer, returns defaultValue.
//
// Example:
//
//	maxConns := getEnvAsInt("MAX_CONNECTIONS", 25)
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnvAsDuration retrieves an environment variable as a time.Duration with a default fallback.
// Supports Go duration format: "300ms", "1.5h", "2h45m", etc.
// If the variable is not set or cannot be parsed, returns defaultValue.
//
// Example:
//
//	timeout := getEnvAsDuration("REQUEST_TIMEOUT", 30*time.Second)
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnvAsSlice retrieves an environment variable as a string slice with a default fallback.
// Parses comma-separated values into a slice.
// If the variable is not set, returns defaultValue.
//
// Example:
//
//	// ALLOWED_ORIGINS=http://localhost:3000,https://example.com
//	origins := getEnvAsSlice("ALLOWED_ORIGINS", []string{"http://localhost:3000"})
//	// Returns: ["http://localhost:3000", "https://example.com"]
func getEnvAsSlice(key string, defaultValue []string) []string {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	// Simple comma-separated parsing
	var result []string
	current := ""
	for _, char := range valueStr {
		if char == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
