package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/middleware"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type MockUserDB struct {
	mock.Mock
}

func (m *MockUserDB) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type MockOAuthService struct {
	mock.Mock
}

func (m *MockOAuthService) GetAuthURL(state string) string {
	args := m.Called(state)
	return args.String(0)
}

func (m *MockOAuthService) AuthenticateUser(ctx context.Context, code string) (*models.User, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email string) (*services.TokenPair, error) {
	args := m.Called(ctx, userID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

func (m *MockJWTService) RefreshAccessToken(ctx context.Context, refreshToken string) (*services.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

func (m *MockJWTService) RevokeToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type MockSessionService struct {
	mock.Mock
}

func (m *MockSessionService) CreateSession(ctx context.Context, userID uuid.UUID, deviceInfo, ipAddress string) (string, error) {
	args := m.Called(ctx, userID, deviceInfo, ipAddress)
	return args.String(0), args.Error(1)
}

func (m *MockSessionService) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.SessionInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SessionInfo), args.Error(1)
}

func (m *MockSessionService) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID string) error {
	args := m.Called(ctx, userID, sessionID)
	return args.Error(0)
}

func (m *MockSessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSessionService) GetGeoLocation(ctx context.Context, ipAddress string) string {
	args := m.Called(ctx, ipAddress)
	return args.String(0)
}

// Test helper functions

func setupAuthHandler(t *testing.T) (*AuthHandler, *MockOAuthService, *MockJWTService, *MockSessionService, *MockUserDB) {
	mockOAuth := new(MockOAuthService)
	mockJWT := new(MockJWTService)
	mockSession := new(MockSessionService)
	mockDB := new(MockUserDB)

	handler := NewAuthHandler(
		mockOAuth,
		mockJWT,
		mockSession,
		mockDB,
		false, // not production (for easier testing with cookies)
		"http://localhost:3000/dashboard",
	)

	return handler, mockOAuth, mockJWT, mockSession, mockDB
}

func testUser() *models.User {
	return &models.User{
		ID:         uuid.New(),
		GoogleID:   "google-123",
		Email:      "test@example.com",
		Name:       "Test User",
		PictureURL: "https://example.com/pic.jpg",
		CreatedAt:  time.Now(),
	}
}

func testTokenPair() *services.TokenPair {
	return &services.TokenPair{
		AccessToken:  "access_token_xyz",
		RefreshToken: "refresh_token_abc",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
	}
}

// Tests

func TestGoogleLogin(t *testing.T) {
	t.Run("redirects to OAuth URL with state cookie", func(t *testing.T) {
		handler, mockOAuth, _, _, _ := setupAuthHandler(t)

		mockOAuth.On("GetAuthURL", mock.Anything).Return("https://accounts.google.com/o/oauth2/auth?client_id=...")

		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)
		rec := httptest.NewRecorder()

		handler.GoogleLogin(rec, req)

		// Assert redirect
		assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "accounts.google.com")

		// Assert state cookie is set
		cookies := rec.Result().Cookies()
		var stateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "oauth_state" {
				stateCookie = c
				break
			}
		}
		require.NotNil(t, stateCookie, "oauth_state cookie should be set")
		assert.NotEmpty(t, stateCookie.Value)
		assert.Equal(t, 600, stateCookie.MaxAge) // 10 minutes

		mockOAuth.AssertExpectations(t)
	})

	t.Run("generates unique state for each request", func(t *testing.T) {
		handler, mockOAuth, _, _, _ := setupAuthHandler(t)

		var states []string
		mockOAuth.On("GetAuthURL", mock.Anything).Return("https://accounts.google.com/oauth").Times(3)

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)
			rec := httptest.NewRecorder()

			handler.GoogleLogin(rec, req)

			cookies := rec.Result().Cookies()
			for _, c := range cookies {
				if c.Name == "oauth_state" {
					states = append(states, c.Value)
				}
			}
		}

		// All states should be unique
		assert.Len(t, states, 3)
		assert.NotEqual(t, states[0], states[1])
		assert.NotEqual(t, states[1], states[2])
	})
}

func TestGoogleCallback(t *testing.T) {
	t.Run("successful authentication flow", func(t *testing.T) {
		handler, mockOAuth, mockJWT, mockSession, _ := setupAuthHandler(t)

		user := testUser()
		tokens := testTokenPair()

		mockOAuth.On("AuthenticateUser", mock.Anything, "valid_code").Return(user, nil)
		mockJWT.On("GenerateTokenPair", mock.Anything, user.ID, user.Email).Return(tokens, nil)
		mockSession.On("CreateSession", mock.Anything, user.ID, mock.Anything, mock.Anything).Return("session_123", nil)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=test_state&code=valid_code", nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test_state"})
		rec := httptest.NewRecorder()

		handler.GoogleCallback(rec, req)

		// Assert redirect to frontend
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "http://localhost:3000/dashboard", rec.Header().Get("Location"))

		// Assert cookies are set
		cookies := rec.Result().Cookies()
		cookieNames := make(map[string]bool)
		for _, c := range cookies {
			cookieNames[c.Name] = true
		}
		assert.True(t, cookieNames["access_token"], "access_token cookie should be set")
		assert.True(t, cookieNames["refresh_token"], "refresh_token cookie should be set")
		assert.True(t, cookieNames["session_id"], "session_id cookie should be set")

		mockOAuth.AssertExpectations(t)
		mockJWT.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("fails on state mismatch", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=wrong_state&code=code", nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "correct_state"})
		rec := httptest.NewRecorder()

		handler.GoogleCallback(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid OAuth state")
	})

	t.Run("fails on missing code", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=test_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test_state"})
		rec := httptest.NewRecorder()

		handler.GoogleCallback(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "authorization code")
	})

	t.Run("fails on authentication error", func(t *testing.T) {
		handler, mockOAuth, _, _, _ := setupAuthHandler(t)

		mockOAuth.On("AuthenticateUser", mock.Anything, "invalid_code").Return(nil, errors.New("authentication failed"))

		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=test_state&code=invalid_code", nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test_state"})
		rec := httptest.NewRecorder()

		handler.GoogleCallback(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		mockOAuth.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("refreshes token from cookie", func(t *testing.T) {
		handler, _, mockJWT, _, _ := setupAuthHandler(t)

		tokens := testTokenPair()
		mockJWT.On("RefreshAccessToken", mock.Anything, "old_refresh_token").Return(tokens, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "old_refresh_token"})
		rec := httptest.NewRecorder()

		handler.RefreshToken(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response services.TokenPair
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, tokens.AccessToken, response.AccessToken)
		assert.Equal(t, tokens.RefreshToken, response.RefreshToken)

		mockJWT.AssertExpectations(t)
	})

	t.Run("refreshes token from request body", func(t *testing.T) {
		handler, _, mockJWT, _, _ := setupAuthHandler(t)

		tokens := testTokenPair()
		mockJWT.On("RefreshAccessToken", mock.Anything, "body_refresh_token").Return(tokens, nil)

		body := map[string]string{"refresh_token": "body_refresh_token"}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.RefreshToken(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		mockJWT.AssertExpectations(t)
	})

	t.Run("fails on missing refresh token", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		// Send empty JSON body (not nil body)
		body := map[string]string{}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.RefreshToken(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Missing refresh token")
	})

	t.Run("fails on invalid refresh token", func(t *testing.T) {
		handler, _, mockJWT, _, _ := setupAuthHandler(t)

		mockJWT.On("RefreshAccessToken", mock.Anything, "invalid_token").Return(nil, errors.New("invalid token"))

		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid_token"})
		rec := httptest.NewRecorder()

		handler.RefreshToken(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		mockJWT.AssertExpectations(t)
	})
}

func TestLogout(t *testing.T) {
	t.Run("revokes tokens and sessions successfully", func(t *testing.T) {
		handler, _, mockJWT, mockSession, _ := setupAuthHandler(t)

		userID := uuid.New()
		mockJWT.On("RevokeToken", mock.Anything, "access_token_value").Return(nil)
		mockJWT.On("RevokeToken", mock.Anything, "refresh_token_value").Return(nil)
		mockSession.On("RevokeAllSessions", mock.Anything, userID).Return(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "access_token_value"})
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh_token_value"})

		// Add user ID to context (would be set by JWT middleware)
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		handler.Logout(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Logged out successfully")

		// Check cookies are cleared
		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == "access_token" || c.Name == "refresh_token" || c.Name == "session_id" {
				assert.Equal(t, -1, c.MaxAge, "Cookie %s should be cleared", c.Name)
			}
		}

		mockJWT.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("handles logout without cookies gracefully", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		rec := httptest.NewRecorder()

		handler.Logout(rec, req)

		// Should still succeed even without cookies
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestMe(t *testing.T) {
	t.Run("returns user profile successfully", func(t *testing.T) {
		handler, _, _, _, mockDB := setupAuthHandler(t)

		user := testUser()
		mockDB.On("GetUserByID", mock.Anything, user.ID).Return(user, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, user.ID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.Me(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		userMap := response["user"].(map[string]interface{})
		assert.Equal(t, user.Email, userMap["email"])
		assert.Equal(t, user.Name, userMap["name"])

		mockDB.AssertExpectations(t)
	})

	t.Run("fails on missing user ID in context", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		rec := httptest.NewRecorder()

		handler.Me(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("fails on database error", func(t *testing.T) {
		handler, _, _, _, mockDB := setupAuthHandler(t)

		userID := uuid.New()
		mockDB.On("GetUserByID", mock.Anything, userID).Return(nil, errors.New("database error"))

		req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.Me(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestListSessions(t *testing.T) {
	t.Run("lists user sessions successfully", func(t *testing.T) {
		handler, _, _, mockSession, _ := setupAuthHandler(t)

		userID := uuid.New()
		sessions := []*models.SessionInfo{
			{
				ID:         "session_1",
				DeviceInfo: "Chrome 120 · Windows 11 · Desktop",
				IPAddress:  "203.0.113.42",
				CreatedAt:  time.Now(),
			},
			{
				ID:         "session_2",
				DeviceInfo: "Safari 17 · iOS 17 · Mobile",
				IPAddress:  "198.51.100.10",
				CreatedAt:  time.Now().Add(-24 * time.Hour),
			},
		}

		mockSession.On("ListUserSessions", mock.Anything, userID).Return(sessions, nil)
		mockSession.On("GetGeoLocation", mock.Anything, "203.0.113.42").Return("San Francisco, 🇺🇸 United States")
		mockSession.On("GetGeoLocation", mock.Anything, "198.51.100.10").Return("New York, 🇺🇸 United States")

		req := httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "session_1"})
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.ListSessions(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		sessionsArray := response["sessions"].([]interface{})
		assert.Len(t, sessionsArray, 2)

		// First session should be marked as current
		firstSession := sessionsArray[0].(map[string]interface{})
		assert.True(t, firstSession["is_current"].(bool))

		mockSession.AssertExpectations(t)
	})

	t.Run("fails without authentication", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		req := httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
		rec := httptest.NewRecorder()

		handler.ListSessions(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestRevokeSession(t *testing.T) {
	t.Run("revokes session successfully", func(t *testing.T) {
		handler, _, _, mockSession, _ := setupAuthHandler(t)

		userID := uuid.New()
		sessionID := "session_to_revoke"

		mockSession.On("RevokeSession", mock.Anything, userID, sessionID).Return(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/"+sessionID, nil)

		// Setup chi context for URL param
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", sessionID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		// Add user ID
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		handler.RevokeSession(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "revoked successfully")

		mockSession.AssertExpectations(t)
	})

	t.Run("fails on missing session ID", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		userID := uuid.New()

		req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/", nil)
		rctx := chi.NewRouteContext()
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.RevokeSession(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestRevokeOtherSessions(t *testing.T) {
	t.Run("revokes all sessions except current", func(t *testing.T) {
		handler, _, _, mockSession, _ := setupAuthHandler(t)

		userID := uuid.New()
		sessions := []*models.SessionInfo{
			{ID: "current_session"},
			{ID: "old_session_1"},
			{ID: "old_session_2"},
		}

		mockSession.On("ListUserSessions", mock.Anything, userID).Return(sessions, nil)
		mockSession.On("RevokeSession", mock.Anything, userID, "old_session_1").Return(nil)
		mockSession.On("RevokeSession", mock.Anything, userID, "old_session_2").Return(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/sessions/revoke-others", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "current_session"})
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.RevokeOtherSessions(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(2), response["revoked_count"])

		mockSession.AssertExpectations(t)
	})

	t.Run("fails without current session cookie", func(t *testing.T) {
		handler, _, _, _, _ := setupAuthHandler(t)

		userID := uuid.New()

		req := httptest.NewRequest(http.MethodPost, "/api/auth/sessions/revoke-others", nil)
		ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID.String())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		handler.RevokeOtherSessions(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Current session not found")
	})
}
