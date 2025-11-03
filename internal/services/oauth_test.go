package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// MockUserDatabase is a mock implementation of UserDatabase
type MockUserDatabase struct {
	mock.Mock
}

func (m *MockUserDatabase) CreateUser(ctx context.Context, googleID, email, name, picture string) (*models.User, error) {
	args := m.Called(ctx, googleID, email, name, picture)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func setupOAuthService(t *testing.T) (*OAuthService, *MockUserDatabase) {
	t.Helper()

	mockDB := new(MockUserDatabase)

	cfg := &config.OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/api/auth/callback",
	}

	// We need to create the service manually to inject the mock
	oauthService := &OAuthService{
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		},
		db: mockDB,
	}

	return oauthService, mockDB
}

func TestGetAuthURL(t *testing.T) {
	oauthService, _ := setupOAuthService(t)

	t.Run("generates valid OAuth URL", func(t *testing.T) {
		state := "random-state-string"
		authURL := oauthService.GetAuthURL(state)

		assert.NotEmpty(t, authURL)
		assert.Contains(t, authURL, "accounts.google.com/o/oauth2/auth")
		assert.Contains(t, authURL, "client_id=test-client-id")
		assert.Contains(t, authURL, "state="+state)
		assert.Contains(t, authURL, "redirect_uri=")
		assert.Contains(t, authURL, "response_type=code")
		assert.Contains(t, authURL, "scope=")
		assert.Contains(t, authURL, "access_type=offline")
	})

	t.Run("includes required scopes", func(t *testing.T) {
		state := "test-state"
		authURL := oauthService.GetAuthURL(state)

		assert.Contains(t, authURL, "userinfo.profile")
		assert.Contains(t, authURL, "userinfo.email")
	})

	t.Run("different states generate different URLs", func(t *testing.T) {
		state1 := "state-1"
		state2 := "state-2"

		url1 := oauthService.GetAuthURL(state1)
		url2 := oauthService.GetAuthURL(state2)

		assert.NotEqual(t, url1, url2)
		assert.Contains(t, url1, state1)
		assert.Contains(t, url2, state2)
	})
}

func TestExchangeCode(t *testing.T) {
	oauthService, _ := setupOAuthService(t)

	t.Run("exchanges code for token with mock server", func(t *testing.T) {
		// Create a mock Google OAuth token endpoint
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify it's a POST request
			assert.Equal(t, http.MethodPost, r.Method)

			// Verify content type
			assert.Contains(t, r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")

			// Parse form to verify parameters
			err := r.ParseForm()
			require.NoError(t, err)

			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "test-auth-code", r.FormValue("code"))
			assert.NotEmpty(t, r.FormValue("redirect_uri"))

			// Return a mock token response
			response := map[string]interface{}{
				"access_token":  "mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock-refresh-token",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer mockServer.Close()

		// Update the service's token endpoint to use our mock server
		oauthService.config.Endpoint.TokenURL = mockServer.URL

		ctx := context.Background()
		token, err := oauthService.ExchangeCode(ctx, "test-auth-code")

		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Equal(t, "mock-access-token", token.AccessToken)
		assert.Equal(t, "mock-refresh-token", token.RefreshToken)
		assert.Equal(t, "Bearer", token.TokenType)
	})

	t.Run("returns error for invalid code", func(t *testing.T) {
		// Create a mock server that returns an error
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
		}))
		defer mockServer.Close()

		oauthService.config.Endpoint.TokenURL = mockServer.URL

		ctx := context.Background()
		_, err := oauthService.ExchangeCode(ctx, "invalid-code")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to exchange code")
	})

	t.Run("handles network errors", func(t *testing.T) {
		// Point to non-existent server
		oauthService.config.Endpoint.TokenURL = "http://localhost:1"

		ctx := context.Background()
		_, err := oauthService.ExchangeCode(ctx, "test-code")

		assert.Error(t, err)
	})
}

func TestGetUserInfo(t *testing.T) {
	oauthService, _ := setupOAuthService(t)

	t.Run("retrieves user info successfully", func(t *testing.T) {
		// Create a mock Google UserInfo API endpoint
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify it's a GET request
			assert.Equal(t, http.MethodGet, r.Method)

			// Verify Authorization header
			authHeader := r.Header.Get("Authorization")
			assert.NotEmpty(t, authHeader)
			assert.Contains(t, authHeader, "Bearer")

			// Return mock user info
			userInfo := GoogleUserInfo{
				ID:      "123456789",
				Email:   "test@example.com",
				Name:    "Test User",
				Picture: "https://example.com/picture.jpg",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(userInfo)
		}))
		defer mockServer.Close()

		// Create a token with the mock server URL
		token := &oauth2.Token{
			AccessToken: "mock-access-token",
			TokenType:   "Bearer",
		}

		// We need to override the transport to use our mock server
		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					// Redirect userinfo requests to our mock server
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(mockServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		userInfo, err := oauthService.GetUserInfo(ctx, token)

		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.Equal(t, "123456789", userInfo.ID)
		assert.Equal(t, "test@example.com", userInfo.Email)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.Equal(t, "https://example.com/picture.jpg", userInfo.Picture)
	})

	t.Run("handles API errors", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_token",
			})
		}))
		defer mockServer.Close()

		token := &oauth2.Token{
			AccessToken: "invalid-token",
			TokenType:   "Bearer",
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(mockServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		_, err := oauthService.GetUserInfo(ctx, token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get user info")
	})

	t.Run("handles malformed JSON", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("invalid json{"))
		}))
		defer mockServer.Close()

		token := &oauth2.Token{
			AccessToken: "mock-token",
			TokenType:   "Bearer",
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(mockServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		_, err := oauthService.GetUserInfo(ctx, token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode user info")
	})
}

func TestAuthenticateUser(t *testing.T) {
	oauthService, mockDB := setupOAuthService(t)

	t.Run("creates new user successfully", func(t *testing.T) {
		// Setup mock server for both token exchange and user info
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"access_token":  "mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock-refresh-token",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer tokenServer.Close()

		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo := GoogleUserInfo{
				ID:      "google-123",
				Email:   "newuser@example.com",
				Name:    "New User",
				Picture: "https://example.com/photo.jpg",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}))
		defer userInfoServer.Close()

		oauthService.config.Endpoint.TokenURL = tokenServer.URL

		// Setup mock database expectation
		expectedUser := &models.User{
			ID:         uuid.New(),
			GoogleID:   "google-123",
			Email:      "newuser@example.com",
			Name:       "New User",
			PictureURL: "https://example.com/photo.jpg",
		}

		mockDB.On("CreateUser",
			mock.Anything,
			"google-123",
			"newuser@example.com",
			"New User",
			"https://example.com/photo.jpg",
		).Return(expectedUser, nil)

		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(userInfoServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		user, err := oauthService.AuthenticateUser(ctx, "test-code")

		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "google-123", user.GoogleID)
		assert.Equal(t, "newuser@example.com", user.Email)
		assert.Equal(t, "New User", user.Name)
		assert.Equal(t, "https://example.com/photo.jpg", user.PictureURL)

		mockDB.AssertExpectations(t)
	})

	t.Run("fails when code exchange fails", func(t *testing.T) {
		// Setup mock server that returns error
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_grant",
			})
		}))
		defer tokenServer.Close()

		oauthService.config.Endpoint.TokenURL = tokenServer.URL

		ctx := context.Background()
		_, err := oauthService.AuthenticateUser(ctx, "invalid-code")

		assert.Error(t, err)
	})

	t.Run("fails when getting user info fails", func(t *testing.T) {
		// Setup token server (succeeds)
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"access_token": "mock-token",
				"token_type":   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer tokenServer.Close()

		// Setup user info server (fails)
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer userInfoServer.Close()

		oauthService.config.Endpoint.TokenURL = tokenServer.URL

		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(userInfoServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		_, err := oauthService.AuthenticateUser(ctx, "test-code")

		assert.Error(t, err)
	})

	t.Run("fails when database create fails", func(t *testing.T) {
		// Setup successful token and user info servers
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]interface{}{
				"access_token": "mock-token",
				"token_type":   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer tokenServer.Close()

		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userInfo := GoogleUserInfo{
				ID:      "google-456",
				Email:   "test@example.com",
				Name:    "Test",
				Picture: "https://example.com/pic.jpg",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		}))
		defer userInfoServer.Close()

		oauthService.config.Endpoint.TokenURL = tokenServer.URL

		// Setup mock database to return error
		mockDB.On("CreateUser",
			mock.Anything,
			"google-456",
			"test@example.com",
			"Test",
			"https://example.com/pic.jpg",
		).Return(nil, assert.AnError)

		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &mockTransport{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/oauth2/v2/userinfo" {
						req.URL = mustParseURL(userInfoServer.URL)
						return http.DefaultTransport.RoundTrip(req)
					}
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		})

		_, err := oauthService.AuthenticateUser(ctx, "test-code")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create user")

		mockDB.AssertExpectations(t)
	})
}

// Helper types for mocking HTTP transport
type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	return u
}
