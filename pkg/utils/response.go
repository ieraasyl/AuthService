// Package utils provides common utility functions for HTTP response handling,
// request ID management, and cookie operations. It includes standardized response
// formats with automatic request ID injection for distributed tracing.
package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// requestIDKey is the context key for request ID
const requestIDKey contextKey = "request_id"

// GetRequestID retrieves the request ID from the context.
// Returns an empty string if the context is nil or no request ID is present.
//
// Example:
//
//	requestID := utils.GetRequestID(r.Context())
//	if requestID != "" {
//	    log.Info().Str("request_id", requestID).Msg("Processing request")
//	}
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// WithRequestID adds a request ID to the context for distributed tracing.
// This is typically called by middleware to inject a unique identifier for each request.
//
// Example:
//
//	ctx := utils.WithRequestID(r.Context(), uuid.New().String())
//	r = r.WithContext(ctx)
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// ErrorResponse represents a standard error response structure.
// It includes the HTTP status text, a custom message, and a request ID for tracing.
type ErrorResponse struct {
	Error     string `json:"error"`                // HTTP status text (e.g., "Bad Request")
	Message   string `json:"message,omitempty"`    // Detailed error message
	RequestID string `json:"request_id,omitempty"` // Request ID for distributed tracing
}

// SuccessResponse represents a standard success response structure.
// It wraps response data with an optional message and request ID.
type SuccessResponse struct {
	Data      interface{} `json:"data,omitempty"`       // Response payload
	Message   string      `json:"message,omitempty"`    // Optional success message
	RequestID string      `json:"request_id,omitempty"` // Request ID for distributed tracing
}

// RespondWithError sends a JSON error response with automatic request ID extraction.
// The request ID is automatically extracted from the request context.
//
// Example:
//
//	if user == nil {
//	    utils.RespondWithError(w, r, http.StatusNotFound, "User not found")
//	    return
//	}
func RespondWithError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	requestID := GetRequestID(r.Context())
	RespondWithErrorAndRequestID(w, statusCode, message, requestID)
}

// RespondWithErrorAndRequestID sends a JSON error response with an explicit request ID.
// Use RespondWithError instead for automatic request ID extraction from context.
func RespondWithErrorAndRequestID(w http.ResponseWriter, statusCode int, message string, requestID string) {
	response := ErrorResponse{
		Error:     http.StatusText(statusCode),
		Message:   message,
		RequestID: requestID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().
			Err(err).
			Str("request_id", requestID).
			Msg("Failed to encode error response")
	}
}

// RespondWithJSON sends a JSON response with the given status code and data.
// The request ID is automatically extracted from the request context.
//
// Example:
//
//	utils.RespondWithJSON(w, r, http.StatusOK, map[string]string{
//	    "status": "success",
//	    "user_id": userID,
//	})
func RespondWithJSON(w http.ResponseWriter, r *http.Request, statusCode int, data interface{}) {
	requestID := GetRequestID(r.Context())
	RespondWithJSONAndRequestID(w, statusCode, data, requestID)
}

// RespondWithJSONAndRequestID sends a JSON response with an explicit request ID.
// Use RespondWithJSON instead for automatic request ID extraction from context.
func RespondWithJSONAndRequestID(w http.ResponseWriter, statusCode int, data interface{}, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().
			Err(err).
			Str("request_id", requestID).
			Msg("Failed to encode JSON response")
	}
}

// RespondWithSuccess sends a standardized success response with HTTP 200 status.
// The data is wrapped in a SuccessResponse structure with automatic request ID.
//
// Example:
//
//	utils.RespondWithSuccess(w, r, map[string]interface{}{
//	    "users": users,
//	    "count": len(users),
//	})
func RespondWithSuccess(w http.ResponseWriter, r *http.Request, data interface{}) {
	requestID := GetRequestID(r.Context())
	RespondWithSuccessAndRequestID(w, data, "", requestID)
}

// RespondWithSuccessAndRequestID sends a standardized success response with an explicit request ID.
// Use RespondWithSuccess instead for automatic request ID extraction from context.
func RespondWithSuccessAndRequestID(w http.ResponseWriter, data interface{}, message string, requestID string) {
	response := SuccessResponse{
		Data:      data,
		Message:   message,
		RequestID: requestID,
	}

	RespondWithJSONAndRequestID(w, http.StatusOK, response, requestID)
}

// RespondWithMessage sends a simple message response with the given status code.
// Useful for endpoints that only need to return a status message.
//
// Example:
//
//	utils.RespondWithMessage(w, r, http.StatusOK, "Session revoked successfully")
func RespondWithMessage(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	requestID := GetRequestID(r.Context())
	RespondWithMessageAndRequestID(w, statusCode, message, requestID)
}

// RespondWithMessageAndRequestID sends a simple message response with an explicit request ID.
// Use RespondWithMessage instead for automatic request ID extraction from context.
func RespondWithMessageAndRequestID(w http.ResponseWriter, statusCode int, message string, requestID string) {
	response := map[string]string{
		"message": message,
	}
	if requestID != "" {
		response["request_id"] = requestID
	}

	RespondWithJSONAndRequestID(w, statusCode, response, requestID)
}

// SetAuthCookie sets an authentication cookie with appropriate security settings.
// In production, the cookie is marked as Secure (HTTPS only). The cookie is always
// HttpOnly and uses SameSite=Lax for CSRF protection.
//
// Example:
//
//	utils.SetAuthCookie(w, "access_token", token, time.Now().Add(15*time.Minute), true)
func SetAuthCookie(w http.ResponseWriter, name, value string, expires time.Time, isProduction bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

// SetAuthCookieWithMaxAge sets an authentication cookie with MaxAge instead of Expires.
// MaxAge is specified in seconds. Useful for short-lived cookies like OAuth state.
//
// Example:
//
//	utils.SetAuthCookieWithMaxAge(w, "oauth_state", state, 600, true) // 10 minutes
func SetAuthCookieWithMaxAge(w http.ResponseWriter, name, value string, maxAge int, isProduction bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// ClearAuthCookie clears a specific authentication cookie by setting MaxAge to -1.
// This instructs the browser to immediately delete the cookie.
//
// Example:
//
//	utils.ClearAuthCookie(w, "access_token")
func ClearAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// ClearAllAuthCookies clears multiple authentication cookies at once.
// Useful during logout to clear all session-related cookies.
//
// Example:
//
//	utils.ClearAllAuthCookies(w, []string{"access_token", "refresh_token", "session_id"})
func ClearAllAuthCookies(w http.ResponseWriter, cookieNames []string) {
	for _, name := range cookieNames {
		ClearAuthCookie(w, name)
	}
}
