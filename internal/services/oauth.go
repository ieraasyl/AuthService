// Package services provides business logic and application services.
// Services coordinate between handlers and database layers, implementing
// authentication flows, session management, and JWT token operations.
//
// The services layer is responsible for:
//   - OAuth 2.0 authentication with Google
//   - JWT access and refresh token generation
//   - Session creation and management
//   - User authentication state
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// UserDatabase defines the interface for user database operations.
// This interface abstracts the database layer for testing and dependency injection.
type UserDatabase interface {
	CreateUser(ctx context.Context, googleID, email, name, picture string) (*models.User, error)
}

// OAuthService handles Google OAuth 2.0 authentication flows.
// It manages the complete OAuth flow including authorization URL generation,
// code exchange, and user profile retrieval from Google.
//
// The service uses offline access to obtain refresh tokens that can be
// used to maintain long-lived sessions.
type OAuthService struct {
	config *oauth2.Config // OAuth configuration with client credentials
	db     UserDatabase   // Database for user persistence
}

// GoogleUserInfo represents user profile data returned from Google's UserInfo API.
// This structure matches the response from https://www.googleapis.com/oauth2/v2/userinfo
//
// JSON response example:
//
//	{
//	  "id": "1234567890",
//	  "email": "user@example.com",
//	  "name": "John Doe",
//	  "picture": "https://lh3.googleusercontent.com/..."
//	}
type GoogleUserInfo struct {
	ID      string `json:"id"`      // Google account unique identifier
	Email   string `json:"email"`   // User's email address
	Name    string `json:"name"`    // Display name from Google profile
	Picture string `json:"picture"` // Profile picture URL
}

// NewOAuthService creates a new OAuth service configured for Google authentication.
// It initializes the OAuth2 configuration with profile and email scopes and
// sets up offline access for refresh token support.
//
// Parameters:
//   - cfg: OAuth configuration including client ID, secret, and redirect URL
//   - db: PostgreSQL database for user persistence
//
// Example:
//
//	oauthSvc := services.NewOAuthService(&config.OAuthConfig{
//	    ClientID:     "123.apps.googleusercontent.com",
//	    ClientSecret: "secret",
//	    RedirectURL:  "http://localhost:8080/api/auth/callback",
//	}, postgresDB)
func NewOAuthService(cfg *config.OAuthConfig, db *database.PostgresDB) *OAuthService {
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	return &OAuthService{
		config: oauthConfig,
		db:     db,
	}
}

// GetAuthURL generates the Google OAuth 2.0 authorization URL.
// This URL should be used to redirect users to Google's consent screen
// where they can authorize the application to access their profile.
//
// Parameters:
//   - state: A random string used for CSRF protection. Must be verified in the callback.
//
// Returns the full authorization URL including all OAuth parameters.
//
// Example:
//
//	state := generateRandomState()
//	authURL := oauthSvc.GetAuthURL(state)
//	// authURL: https://accounts.google.com/o/oauth2/auth?client_id=...&state=xyz&...
//	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
func (s *OAuthService) GetAuthURL(state string) string {
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges an OAuth authorization code for an access token.
// This is called in the OAuth callback after the user has authorized the application.
// The resulting token includes both an access token (for API calls) and optionally
// a refresh token (for offline access).
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - code: The authorization code received from Google in the callback
//
// Returns the OAuth token or an error if the exchange fails.
// Common failure reasons: invalid code, expired code, network errors.
//
// Example:
//
//	code := r.URL.Query().Get("code")
//	token, err := oauthSvc.ExchangeCode(ctx, code)
//	if err != nil {
//	    return fmt.Errorf("code exchange failed: %w", err)
//	}
func (s *OAuthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange authorization code")
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	return token, nil
}

// GetUserInfo fetches user profile information from Google's UserInfo API.
// This endpoint returns basic profile information including email, name, and
// profile picture. The access token in the provided OAuth token is used for
// authentication.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - token: Valid OAuth token obtained from ExchangeCode
//
// Returns the user's Google profile information or an error if the request fails.
// Common failure reasons: invalid token, expired token, API rate limits, network errors.
//
// Example:
//
//	userInfo, err := oauthSvc.GetUserInfo(ctx, token)
//	if err != nil {
//	    return fmt.Errorf("failed to get user info: %w", err)
//	}
//	fmt.Printf("User: %s (%s)\n", userInfo.Name, userInfo.Email)
func (s *OAuthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
	client := s.config.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch user info from Google")
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Error().Err(err).Msg("Failed to decode user info")
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}

// AuthenticateUser handles the complete OAuth authentication flow.
// This is the high-level method that coordinates:
//  1. Exchanging the authorization code for tokens
//  2. Fetching user profile from Google
//  3. Creating or updating the user in the database
//
// This method implements the "upsert" pattern - if the user exists (based on
// Google ID), their profile is updated; otherwise a new user is created.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - code: Authorization code from the OAuth callback
//
// Returns the authenticated user model or an error if any step fails.
//
// Example:
//
//	code := r.URL.Query().Get("code")
//	user, err := oauthSvc.AuthenticateUser(ctx, code)
//	if err != nil {
//	    log.Error().Err(err).Msg("Authentication failed")
//	    return nil, err
//	}
//	// Create session for authenticated user
//	session, err := sessionSvc.CreateSession(ctx, user.ID, deviceInfo, ipAddr)
func (s *OAuthService) AuthenticateUser(ctx context.Context, code string) (*models.User, error) {
	// Exchange code for token
	token, err := s.ExchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Get user info from Google
	googleUser, err := s.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// Create or update user in database
	user, err := s.db.CreateUser(ctx, googleUser.ID, googleUser.Email, googleUser.Name, googleUser.Picture)
	if err != nil {
		log.Error().
			Err(err).
			Str("google_id", googleUser.ID).
			Str("email", googleUser.Email).
			Msg("Failed to create/update user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	log.Info().
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Msg("User authenticated successfully")

	return user, nil
}
