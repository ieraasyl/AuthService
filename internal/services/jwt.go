package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/rs/zerolog/log"
)

// RedisStore defines the interface for Redis operations needed by JWT service.
// This interface abstracts Redis operations for refresh token storage and
// token blacklisting, enabling testing and dependency injection.
type RedisStore interface {
	SetRefreshToken(ctx context.Context, tokenID, userID string, expiry time.Duration) error
	GetRefreshToken(ctx context.Context, tokenID string) (string, error)
	DeleteRefreshToken(ctx context.Context, tokenID string) error
	BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)
}

// JWTService handles JWT token generation, validation, and lifecycle management.
// It provides:
//   - Token pair generation (access + refresh tokens)
//   - Token validation with blacklist checking
//   - Token refresh using valid refresh tokens
//   - Token revocation via blacklisting
//
// Tokens use HS256 signing and include custom claims for user identity.
// Refresh tokens are stored in Redis for validation, and revoked tokens
// are blacklisted for their remaining lifetime.
type JWTService struct {
	secret        []byte        // Secret key for JWT signing (HS256)
	accessExpiry  time.Duration // Access token lifetime (default: 15 minutes)
	refreshExpiry time.Duration // Refresh token lifetime (default: 7 days)
	redis         RedisStore    // Redis for refresh token storage and blacklisting
}

// TokenPair represents a complete authentication token set returned to clients.
// Contains both an access token (for API requests) and a refresh token
// (for obtaining new access tokens when the current one expires).
//
// Example JSON response:
//
//	{
//	  "access_token": "eyJhbGciOiJIUzI1NiIs...",
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
//	  "expires_at": "2024-01-20T15:00:00Z"
//	}
type TokenPair struct {
	AccessToken  string    `json:"access_token"`  // JWT access token for API authentication
	RefreshToken string    `json:"refresh_token"` // JWT refresh token for token renewal
	ExpiresAt    time.Time `json:"expires_at"`    // Access token expiration time
}

// Claims represents the custom JWT claims embedded in tokens.
// Extends the standard JWT claims with application-specific fields
// for user identification and token tracking.
type Claims struct {
	UserID               string `json:"user_id"` // UUID of the authenticated user
	Email                string `json:"email"`   // User's email for display purposes
	JTI                  string `json:"jti"`     // Unique token ID for blacklisting
	jwt.RegisteredClaims        // Standard JWT claims (exp, iat, nbf)
}

// NewJWTService creates a new JWT service with the provided configuration.
// The service will use the configured secret for token signing and the
// specified expiry durations for access and refresh tokens.
//
// Parameters:
//   - cfg: JWT configuration including secret and expiry times
//   - redis: Redis database for token storage and blacklisting
//
// Example:
//
//	jwtSvc := services.NewJWTService(&config.JWTConfig{
//	    Secret:        []byte("your-secret-key-min-32-bytes"),
//	    AccessExpiry:  15 * time.Minute,
//	    RefreshExpiry: 7 * 24 * time.Hour,
//	}, redisDB)
func NewJWTService(cfg *config.JWTConfig, redis *database.RedisDB) *JWTService {
	return &JWTService{
		secret:        cfg.Secret,
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
		redis:         redis,
	}
}

// GenerateTokenPair creates access and refresh tokens for a user.
// This is the primary method for creating authenticated tokens after successful login.
// It generates:
//  1. An access token (short-lived, default 15 minutes) for API authentication
//  2. A refresh token (long-lived, default 7 days) for obtaining new access tokens
//
// The refresh token is stored in Redis for validation during token refresh.
// Each token has a unique JTI (JWT ID) for tracking and blacklisting.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: UUID of the authenticated user
//   - email: User's email for inclusion in token claims
//
// Returns a TokenPair with both tokens and access token expiration time,
// or an error if generation or storage fails.
//
// Example:
//
//	tokenPair, err := jwtSvc.GenerateTokenPair(ctx, user.ID, user.Email)
//	if err != nil {
//	    return fmt.Errorf("token generation failed: %w", err)
//	}
//	// Set cookies or return in response
//	http.SetCookie(w, &http.Cookie{
//	    Name:     "access_token",
//	    Value:    tokenPair.AccessToken,
//	    Expires:  tokenPair.ExpiresAt,
//	    HttpOnly: true,
//	    Secure:   true,
//	})
func (s *JWTService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email string) (*TokenPair, error) {
	// Generate access token
	accessJTI := generateJTI()
	accessToken, expiresAt, err := s.generateToken(userID.String(), email, accessJTI, s.accessExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshJTI := generateJTI()
	refreshToken, _, err := s.generateToken(userID.String(), email, refreshJTI, s.refreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in Redis
	if err := s.redis.SetRefreshToken(ctx, refreshJTI, userID.String(), s.refreshExpiry); err != nil {
		log.Error().Err(err).Msg("Failed to store refresh token in Redis")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	log.Info().
		Str("user_id", userID.String()).
		Str("access_jti", accessJTI).
		Str("refresh_jti", refreshJTI).
		Msg("Token pair generated successfully")

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// generateToken creates a JWT token with the specified claims and expiry.
// This is an internal helper method used by GenerateTokenPair.
//
// The token is signed using HS256 (HMAC-SHA256) with the configured secret.
// Standard JWT claims (exp, iat, nbf) are set automatically.
//
// Parameters:
//   - userID: User's UUID as string
//   - email: User's email address
//   - jti: Unique JWT ID for this token
//   - expiry: How long the token should be valid
//
// Returns the signed token string, expiration time, and any error.
func (s *JWTService) generateToken(userID, email, jti string, expiry time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(expiry)

	claims := Claims{
		UserID: userID,
		Email:  email,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims if valid.
// Performs comprehensive validation including:
//  1. Signature verification using the configured secret
//  2. Expiration time checking
//  3. Blacklist verification (for revoked tokens)
//
// This method should be used in authentication middleware to verify
// access tokens before granting access to protected endpoints.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tokenString: The JWT token string to validate
//
// Returns the parsed claims if valid, or an error if:
//   - Token signature is invalid
//   - Token has expired
//   - Token has been revoked (blacklisted)
//   - Token format is malformed
//
// Example:
//
//	claims, err := jwtSvc.ValidateToken(ctx, tokenString)
//	if err != nil {
//	    return nil, fmt.Errorf("unauthorized: %w", err)
//	}
//	userID, _ := uuid.Parse(claims.UserID)
func (s *JWTService) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if token is blacklisted
	blacklisted, err := s.redis.IsTokenBlacklisted(ctx, claims.JTI)
	if err != nil {
		log.Error().Err(err).Str("jti", claims.JTI).Msg("Failed to check token blacklist")
		return nil, fmt.Errorf("failed to verify token status: %w", err)
	}
	if blacklisted {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token.
// This implements the token refresh flow, allowing clients to obtain new access
// tokens without requiring full re-authentication.
//
// The process:
//  1. Validates the refresh token
//  2. Verifies it exists in Redis (hasn't been revoked)
//  3. Generates a new token pair
//  4. Deletes the old refresh token (rotation for security)
//
// Token rotation ensures that each refresh token can only be used once,
// improving security by making token theft less valuable.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - refreshTokenString: The refresh token to exchange
//
// Returns a new TokenPair with fresh access and refresh tokens,
// or an error if the refresh token is invalid, expired, or revoked.
//
// Example:
//
//	newTokens, err := jwtSvc.RefreshAccessToken(ctx, oldRefreshToken)
//	if err != nil {
//	    // Refresh token invalid - user must re-authenticate
//	    return errors.New("please log in again")
//	}
//	// Update cookies with new tokens
func (s *JWTService) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := s.ValidateToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify refresh token exists in Redis
	storedUserID, err := s.redis.GetRefreshToken(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", err)
	}

	if storedUserID != claims.UserID {
		return nil, fmt.Errorf("token user mismatch")
	}

	// Parse user ID
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Generate new token pair
	tokenPair, err := s.GenerateTokenPair(ctx, userID, claims.Email)
	if err != nil {
		return nil, err
	}

	// Delete old refresh token from Redis
	if err := s.redis.DeleteRefreshToken(ctx, claims.JTI); err != nil {
		log.Warn().Err(err).Str("jti", claims.JTI).Msg("Failed to delete old refresh token")
	}

	log.Info().
		Str("user_id", claims.UserID).
		Msg("Access token refreshed successfully")

	return tokenPair, nil
}

// RevokeToken adds a token to the blacklist, immediately invalidating it.
// This is used for logout functionality and security operations like
// "revoke all sessions" or responding to compromised credentials.
//
// The token is added to a Redis blacklist with a TTL equal to its
// remaining lifetime. Once expired naturally, it's automatically removed
// from the blacklist (no cleanup needed).
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tokenString: The JWT token to revoke
//
// Returns an error if blacklisting fails. Returns nil if the token is
// already expired (no need to blacklist).
//
// Example:
//
//	// Logout endpoint
//	if err := jwtSvc.RevokeToken(ctx, accessToken); err != nil {
//	    log.Error().Err(err).Msg("Failed to revoke token")
//	}
//	// Token is now blacklisted and will fail validation
func (s *JWTService) RevokeToken(ctx context.Context, tokenString string) error {
	// Parse token to get JTI and expiration
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})

	if err != nil {
		// Even if parsing fails, we might want to try to revoke it
		log.Warn().Err(err).Msg("Failed to parse token for revocation")
		return nil
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// Calculate remaining TTL
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	// Add to blacklist
	if err := s.redis.BlacklistToken(ctx, claims.JTI, ttl); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	log.Info().
		Str("jti", claims.JTI).
		Str("user_id", claims.UserID).
		Msg("Token revoked successfully")

	return nil
}

// generateJTI generates a unique JWT ID using cryptographically secure random bytes.
// JTI (JWT ID) is used for:
//   - Uniquely identifying tokens for blacklisting
//   - Tracking token usage in logs
//   - Implementing token rotation
//
// Returns a URL-safe base64-encoded string of 16 random bytes.
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateState generates a random state string for OAuth CSRF protection.
// The state parameter is used in OAuth flows to prevent cross-site request
// forgery attacks by ensuring the callback matches the original request.
//
// This should be:
//  1. Generated before redirecting to OAuth provider
//  2. Stored in a secure session cookie
//  3. Validated when the user returns from OAuth callback
//
// Returns a URL-safe base64-encoded string of 16 random bytes.
//
// Example:
//
//	// Before OAuth redirect
//	state := services.GenerateState()
//	http.SetCookie(w, &http.Cookie{
//	    Name:     "oauth_state",
//	    Value:    state,
//	    HttpOnly: true,
//	    Secure:   true,
//	    SameSite: http.SameSiteLaxMode,
//	})
//	authURL := oauthSvc.GetAuthURL(state)
//	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
