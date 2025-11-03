package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/middleware"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/internal/services"
	"github.com/ieraasyl/AuthService/pkg/utils"
	"github.com/rs/zerolog/log"
)

// UserDB defines the interface for user database operations.
// Abstracts database access for testing and dependency injection.
type UserDB interface {
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
}

// OAuthService defines the interface for OAuth 2.0 operations.
// Handles Google OAuth authentication flow.
type OAuthService interface {
	GetAuthURL(state string) string
	AuthenticateUser(ctx context.Context, code string) (*models.User, error)
}

// JWTService defines the interface for JWT token operations.
// Manages token lifecycle including generation, validation, and revocation.
type JWTService interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, email string) (*services.TokenPair, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (*services.TokenPair, error)
	RevokeToken(ctx context.Context, token string) error
}

// SessionService defines the interface for session management operations.
// Tracks user sessions with device and location information.
type SessionService interface {
	CreateSession(ctx context.Context, userID uuid.UUID, deviceInfo, ipAddress string) (string, error)
	ListUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.SessionInfo, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
	GetGeoLocation(ctx context.Context, ipAddress string) string
}

// AuthHandler handles all authentication-related HTTP endpoints.
// Provides a complete authentication system including:
//   - OAuth 2.0 login via Google
//   - JWT token management (access & refresh)
//   - Session tracking and management
//   - User profile access
//
// The handler coordinates between OAuth, JWT, and session services to
// provide a complete authentication experience with security features
// like CSRF protection, token rotation, and multi-device session management.
type AuthHandler struct {
	oauthService         OAuthService   // Google OAuth integration
	jwtService           JWTService     // JWT token operations
	sessionService       SessionService // Session management
	db                   UserDB         // User data access
	isProduction         bool           // Production mode flag (affects cookie settings)
	postLoginRedirectURL string         // Where to redirect after successful login
}

// NewAuthHandler creates a new authentication handler with all required dependencies.
//
// Parameters:
//   - oauthService: Service for Google OAuth operations
//   - jwtService: Service for JWT token management
//   - sessionService: Service for session tracking
//   - db: Database for user data access
//   - isProduction: Whether to use secure cookie settings (true in production)
//   - postLoginRedirectURL: Frontend URL to redirect after login (e.g., "https://app.example.com/dashboard")
//
// Example:
//
//	authHandler := handlers.NewAuthHandler(
//	    oauthSvc,
//	    jwtSvc,
//	    sessionSvc,
//	    postgresDB,
//	    true, // production mode
//	    "https://app.example.com/dashboard",
//	)
//
//	// Register routes
//	r.Get("/api/auth/google/login", authHandler.GoogleLogin)
//	r.Get("/api/auth/google/callback", authHandler.GoogleCallback)
func NewAuthHandler(
	oauthService OAuthService,
	jwtService JWTService,
	sessionService SessionService,
	db UserDB,
	isProduction bool,
	postLoginRedirectURL string,
) *AuthHandler {
	return &AuthHandler{
		oauthService:         oauthService,
		jwtService:           jwtService,
		sessionService:       sessionService,
		db:                   db,
		isProduction:         isProduction,
		postLoginRedirectURL: postLoginRedirectURL,
	}
}

// GoogleLogin initiates the Google OAuth 2.0 authentication flow.
// This is the entry point for user login. It generates a CSRF protection
// state token, stores it in a secure cookie, and redirects the user to
// Google's consent screen.
//
// Flow:
//  1. Generate random state string for CSRF protection
//  2. Store state in HttpOnly cookie (10 minute expiry)
//  3. Redirect to Google OAuth authorization URL
//
// The state parameter prevents CSRF attacks by ensuring the callback
// matches this original request.
//
// Cookie settings:
//   - HttpOnly: Prevents JavaScript access
//   - Secure: HTTPS only (in production)
//   - SameSite=Lax: CSRF protection
//   - MaxAge: 600 seconds (10 minutes)
//
// Example usage:
//
//	// Frontend initiates login
//	window.location.href = "/api/auth/google/login"
//	// User is redirected to Google consent screen
//
// @Summary      Initiate Google OAuth login
// @Description  Redirects to Google OAuth consent screen. Sets state cookie for CSRF protection.
// @Tags         auth
// @Produce      html
// @Success      307  {string}  string  "Redirect to Google OAuth"
// @Router       /api/v1/auth/google/login [get]
func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate and store state for CSRF protection
	state := services.GenerateState()

	// Store state in cookie with MaxAge
	utils.SetAuthCookieWithMaxAge(w, "oauth_state", state, 600, h.isProduction) // 10 minutes

	// Redirect to Google OAuth
	authURL := h.oauthService.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback handles the OAuth 2.0 callback from Google.
// This is where Google redirects the user after they grant consent.
// Completes the authentication flow by exchanging the authorization code
// for user information and creating an authenticated session.
//
// Flow:
//  1. Verify CSRF state token matches stored cookie
//  2. Exchange authorization code for user data
//  3. Create or update user in database
//  4. Generate JWT access and refresh tokens
//  5. Create session with device and location info
//  6. Set authentication cookies
//  7. Redirect to frontend application
//
// Security measures:
//   - State verification (CSRF protection)
//   - Token rotation (each refresh invalidates previous)
//   - Session tracking (device fingerprinting)
//   - Secure cookies (HttpOnly, Secure in production)
//
// Cookies set:
//   - access_token: JWT for API authentication (15 min)
//   - refresh_token: JWT for token renewal (7 days)
//   - session_id: Session tracking identifier (7 days)
//
// Query parameters:
//   - state: CSRF protection token (must match cookie)
//   - code: Authorization code from Google
//
// Example callback URL:
//
//	https://api.example.com/api/auth/google/callback?state=xyz&code=abc123
//
// @Summary      Google OAuth callback
// @Description  Handles callback from Google OAuth. Exchanges code for user info and creates session.
// @Tags         auth
// @Produce      html
// @Param        state  query  string  true  "OAuth state (CSRF protection)"
// @Param        code   query  string  true  "Authorization code from Google"
// @Success      303    {string}  string  "Redirect to frontend"
// @Failure      400    {object}  utils.ErrorResponse  "Invalid state or missing code"
// @Failure      401    {object}  utils.ErrorResponse  "Authentication failed"
// @Failure      500    {object}  utils.ErrorResponse  "Internal server error"
// @Router       /api/v1/auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state parameter
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		log.Warn().Err(err).Msg("Missing OAuth state cookie")
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid OAuth state")
		return
	}

	stateParam := r.URL.Query().Get("state")
	if stateParam != stateCookie.Value {
		log.Warn().Msg("OAuth state mismatch")
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid OAuth state")
		return
	}

	// Clear state cookie
	utils.ClearAuthCookie(w, "oauth_state")

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Warn().Msg("Missing authorization code")
		utils.RespondWithError(w, r, http.StatusBadRequest, "Missing authorization code")
		return
	}

	// Authenticate user
	user, err := h.oauthService.AuthenticateUser(r.Context(), code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to authenticate user")
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Authentication failed")
		return
	}

	// Generate token pair
	tokens, err := h.jwtService.GenerateTokenPair(r.Context(), user.ID, user.Email)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate tokens")
		utils.RespondWithError(w, r, http.StatusInternalServerError, "Failed to generate tokens")
		return
	}

	// Extract device info and IP
	deviceInfo := services.ExtractDeviceInfo(r.UserAgent())
	ipAddress := utils.ExtractClientIP(r)

	// Create session
	sessionID, err := h.sessionService.CreateSession(r.Context(), user.ID, deviceInfo, ipAddress)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session")
		// Continue even if session creation fails
	}

	// Set tokens in cookies
	utils.SetAuthCookie(w, "access_token", tokens.AccessToken, tokens.ExpiresAt, h.isProduction)
	utils.SetAuthCookie(w, "refresh_token", tokens.RefreshToken, time.Now().Add(168*time.Hour), h.isProduction)

	// Store session ID in cookie
	utils.SetAuthCookie(w, "session_id", sessionID, time.Now().Add(168*time.Hour), h.isProduction)

	// Redirect back to the frontend application
	redirectURL := h.postLoginRedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// RefreshToken generates a new access token using a valid refresh token.
// Implements the token refresh flow to maintain authenticated sessions
// without requiring users to log in again.
//
// Token rotation security:
//   - Each refresh generates a NEW refresh token
//   - Old refresh token is immediately invalidated
//   - Prevents token replay attacks
//
// Request options (accepts both):
//  1. Cookie: refresh_token=<token>
//  2. JSON body: {"refresh_token": "<token>"}
//
// Response includes both new access and refresh tokens in cookies and JSON.
//
// Example request (cookie-based):
//
//	POST /api/auth/refresh
//	Cookie: refresh_token=eyJhbGci...
//
// Example request (JSON body):
//
//	POST /api/auth/refresh
//	Content-Type: application/json
//	{"refresh_token": "eyJhbGci..."}
//
// Response:
//
//	{
//	  "access_token": "eyJhbGci...",
//	  "refresh_token": "eyJhbGci...",
//	  "expires_at": "2024-01-20T15:00:00Z"
//	}
//
// @Summary      Refresh access token
// @Description  Generates new access and refresh tokens using a valid refresh token. Implements token rotation.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object  false  "Refresh token (optional if in cookie)"  example({"refresh_token": "eyJhbGci..."})
// @Success      200   {object}  services.TokenPair  "New token pair"
// @Failure      400   {object}  utils.ErrorResponse  "Invalid request or missing token"
// @Failure      401   {object}  utils.ErrorResponse  "Invalid or expired refresh token"
// @Router       /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from cookie or request body
	var refreshToken string

	// Try cookie first
	cookie, err := r.Cookie("refresh_token")
	if err == nil {
		refreshToken = cookie.Value
	} else {
		// Try request body
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid request")
			return
		}
		refreshToken = req.RefreshToken
	}

	if refreshToken == "" {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Missing refresh token")
		return
	}

	// Refresh access token
	tokens, err := h.jwtService.RefreshAccessToken(r.Context(), refreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to refresh token")
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Set new tokens in cookies
	utils.SetAuthCookie(w, "access_token", tokens.AccessToken, tokens.ExpiresAt, h.isProduction)
	utils.SetAuthCookie(w, "refresh_token", tokens.RefreshToken, time.Now().Add(168*time.Hour), h.isProduction)

	// Respond with new tokens
	utils.RespondWithJSON(w, r, http.StatusOK, tokens)
}

// Logout logs out the user from the current session.
// Performs a complete logout by:
//  1. Revoking access and refresh tokens (blacklisting)
//  2. Deleting all user sessions from Redis
//  3. Clearing authentication cookies
//
// This effectively logs the user out from ALL devices, not just the current one.
// For single-device logout, use RevokeSession instead.
//
// Token revocation:
//   - Tokens are added to Redis blacklist
//   - Blacklist entries expire when tokens would naturally expire
//   - Prevents use of stolen tokens even if attacker has the cookie
//
// Security note: This endpoint should be called before sensitive operations
// like password changes to ensure no lingering sessions remain.
//
// Example request:
//
//	POST /api/auth/logout
//	Cookie: access_token=...; refresh_token=...
//
// Response:
//
//	{
//	  "message": "Logged out successfully"
//	}
//
// @Summary      Logout user
// @Description  Revokes all tokens and sessions. Clears authentication cookies. Logs out from all devices.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  map[string]string  "Logged out successfully"
// @Router       /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get tokens from cookies
	accessCookie, _ := r.Cookie("access_token")
	refreshCookie, _ := r.Cookie("refresh_token")

	// Revoke access token
	if accessCookie != nil {
		if err := h.jwtService.RevokeToken(r.Context(), accessCookie.Value); err != nil {
			log.Warn().Err(err).Msg("Failed to revoke access token")
		}
	}

	// Revoke refresh token
	if refreshCookie != nil {
		if err := h.jwtService.RevokeToken(r.Context(), refreshCookie.Value); err != nil {
			log.Warn().Err(err).Msg("Failed to revoke refresh token")
		}
	}

	// Get user ID from context and revoke all sessions
	if userID, ok := middleware.GetUserID(r.Context()); ok {
		uid, err := uuid.Parse(userID)
		if err == nil {
			if err := h.sessionService.RevokeAllSessions(r.Context(), uid); err != nil {
				log.Warn().Err(err).Msg("Failed to revoke sessions")
			}
		}
	}

	// Clear cookies
	utils.ClearAllAuthCookies(w, []string{"access_token", "refresh_token", "session_id"})

	utils.RespondWithMessage(w, r, http.StatusOK, "Logged out successfully")
}

// Me returns the current authenticated user's profile information.
// This is a protected endpoint that requires a valid JWT access token.
// The user ID is extracted from the JWT claims by the authentication middleware.
//
// Used by frontends to:
//   - Display user profile
//   - Check authentication status
//   - Get user data after login
//
// Requires: JWT authentication middleware
//
// Example request:
//
//	GET /api/auth/me
//	Cookie: access_token=eyJhbGci...
//
// Response:
//
//	{
//	  "user": {
//	    "id": "550e8400-e29b-41d4-a716-446655440000",
//	    "email": "user@example.com",
//	    "name": "John Doe",
//	    "picture_url": "https://lh3.googleusercontent.com/...",
//	    "created_at": "2024-01-15T10:30:00Z"
//	  }
//	}
//
// @Summary      Get current user profile
// @Description  Returns authenticated user's information from JWT claims
// @Tags         auth
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  map[string]interface{}  "User profile"
// @Failure      401  {object}  utils.ErrorResponse     "Unauthorized or invalid token"
// @Failure      500  {object}  utils.ErrorResponse     "Failed to fetch user"
// @Router       /api/v1/auth/me [get]
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by JWT middleware)
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Parse user ID
	uid, err := uuid.Parse(userID)
	if err != nil {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get full user info from database
	user, err := h.db.GetUserByID(r.Context(), uid)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("Failed to fetch user")
		utils.RespondWithError(w, r, http.StatusInternalServerError, "Failed to fetch user information")
		return
	}

	utils.RespondWithJSON(w, r, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

// ListSessions lists all active sessions for the current user.
// Returns session information including device type, location, and last activity.
// Used by the "Active Sessions" or "Devices" UI feature.
//
// Each session includes:
//   - Unique session ID
//   - Device info (browser, OS, device type)
//   - Geographic location (from IP address)
//   - Last activity timestamp
//   - Current session indicator
//
// Geolocation is cached for 24 hours to minimize API calls.
// The current session is marked with `is_current: true`.
//
// Requires: JWT authentication middleware
//
// Example request:
//
//	GET /api/auth/sessions
//	Cookie: access_token=...; session_id=...
//
// Response:
//
//	{
//	  "sessions": [
//	    {
//	      "id": "sess_abc123",
//	      "device": "Chrome 120 · Windows 11 · Desktop",
//	      "location": "San Francisco, 🇺🇸 United States",
//	      "ip_address": "203.0.113.42",
//	      "last_used": "2024-01-20T14:30:00Z",
//	      "is_current": true
//	    },
//	    {
//	      "id": "sess_xyz789",
//	      "device": "Safari 17 · iOS 17.1 · Mobile",
//	      "location": "New York, 🇺🇸 United States",
//	      "ip_address": "198.51.100.10",
//	      "last_used": "2024-01-19T09:15:00Z",
//	      "is_current": false
//	    }
//	  ]
//	}
//
// @Summary      List active sessions
// @Description  Returns all active sessions for the authenticated user with device and location info
// @Tags         auth
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  map[string]interface{}  "List of sessions"
// @Failure      401  {object}  utils.ErrorResponse     "Unauthorized"
// @Failure      500  {object}  utils.ErrorResponse     "Failed to list sessions"
// @Router       /api/v1/auth/sessions [get]
func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get current session ID from cookie
	currentSessionID := ""
	if sessionCookie, err := r.Cookie("session_id"); err == nil {
		currentSessionID = sessionCookie.Value
	}

	// List sessions
	sessions, err := h.sessionService.ListUserSessions(r.Context(), uid)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list sessions")
		utils.RespondWithError(w, r, http.StatusInternalServerError, "Failed to list sessions")
		return
	}

	// Add current session indicator and format for frontend
	type SessionResponse struct {
		ID        string `json:"id"`
		Device    string `json:"device"`
		Location  string `json:"location"`
		IPAddress string `json:"ip_address"`
		LastUsed  string `json:"last_used"`
		IsCurrent bool   `json:"is_current"`
	}

	response := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		response[i] = SessionResponse{
			ID:        session.ID,
			Device:    session.DeviceInfo,
			Location:  h.sessionService.GetGeoLocation(r.Context(), session.IPAddress),
			IPAddress: session.IPAddress,
			LastUsed:  session.CreatedAt.Format(time.RFC3339),
			IsCurrent: session.ID == currentSessionID,
		}
	}

	utils.RespondWithJSON(w, r, http.StatusOK, map[string]interface{}{
		"sessions": response,
	})
}

// RevokeSession revokes a specific session, logging out that device only.
// Allows users to remotely log out individual devices while keeping
// others active. Useful when a device is lost or no longer in use.
//
// The session ID is passed as a URL parameter: /api/auth/sessions/{id}
// Users can get session IDs from the ListSessions endpoint.
//
// Requires: JWT authentication middleware
//
// Example request:
//
//	DELETE /api/auth/sessions/sess_abc123
//	Cookie: access_token=...
//
// Response:
//
//	{
//	  "message": "Session revoked successfully"
//	}
//
// @Summary      Revoke a session
// @Description  Logs out a specific device/session by session ID
// @Tags         auth
// @Produce      json
// @Security     CookieAuth
// @Param        id   path      string  true  "Session ID"
// @Success      200  {object}  map[string]string   "Session revoked"
// @Failure      400  {object}  utils.ErrorResponse "Missing session ID"
// @Failure      401  {object}  utils.ErrorResponse "Unauthorized"
// @Failure      500  {object}  utils.ErrorResponse "Failed to revoke session"
// @Router       /api/v1/auth/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get session ID from URL
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Missing session ID")
		return
	}

	// Revoke session
	if err := h.sessionService.RevokeSession(r.Context(), uid, sessionID); err != nil {
		log.Error().Err(err).Msg("Failed to revoke session")
		utils.RespondWithError(w, r, http.StatusInternalServerError, "Failed to revoke session")
		return
	}

	utils.RespondWithMessage(w, r, http.StatusOK, "Session revoked successfully")
}

// RevokeOtherSessions revokes all sessions except the current one.
// Implements "Log out all other devices" functionality. Useful when
// users want to ensure only their current device has access.
//
// Common use cases:
//   - Security: User suspects account compromise
//   - Convenience: Clean up old/unused sessions
//   - Policy: Enforce single-device usage
//
// The current session is identified by the session_id cookie and
// remains active. All other sessions are terminated.
//
// Requires: JWT authentication middleware
//
// Example request:
//
//	POST /api/auth/sessions/revoke-others
//	Cookie: access_token=...; session_id=sess_current123
//
// Response:
//
//	{
//	  "message": "Other sessions revoked successfully",
//	  "revoked_count": 3
//	}
//
// @Summary      Revoke all other sessions
// @Description  Logs out all devices except the current one
// @Tags         auth
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  map[string]interface{}  "Sessions revoked"
// @Failure      400  {object}  utils.ErrorResponse     "Current session not found"
// @Failure      401  {object}  utils.ErrorResponse     "Unauthorized"
// @Failure      500  {object}  utils.ErrorResponse     "Failed to revoke sessions"
// @Router       /api/v1/auth/sessions/revoke-others [post]
func (h *AuthHandler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		utils.RespondWithError(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get current session ID from cookie
	currentSessionID := ""
	if sessionCookie, err := r.Cookie("session_id"); err == nil {
		currentSessionID = sessionCookie.Value
	}

	if currentSessionID == "" {
		utils.RespondWithError(w, r, http.StatusBadRequest, "Current session not found")
		return
	}

	// Get all sessions
	sessions, err := h.sessionService.ListUserSessions(r.Context(), uid)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list sessions")
		utils.RespondWithError(w, r, http.StatusInternalServerError, "Failed to list sessions")
		return
	}

	// Revoke all except current
	revokedCount := 0
	for _, session := range sessions {
		if session.ID != currentSessionID {
			if err := h.sessionService.RevokeSession(r.Context(), uid, session.ID); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", session.ID).
					Msg("Failed to revoke session")
			} else {
				revokedCount++
			}
		}
	}

	log.Info().
		Str("user_id", userID).
		Int("revoked_count", revokedCount).
		Msg("Other sessions revoked")

	utils.RespondWithJSON(w, r, http.StatusOK, map[string]interface{}{
		"message":       "Other sessions revoked successfully",
		"revoked_count": revokedCount,
	})
}
