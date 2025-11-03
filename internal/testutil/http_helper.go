package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MakeRequest creates and executes an HTTP request for testing
func MakeRequest(t *testing.T, method, url string, body interface{}) *http.Request {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req := httptest.NewRequest(method, url, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req
}

// ParseJSONResponse parses a JSON response into the provided interface
func ParseJSONResponse(t *testing.T, resp *httptest.ResponseRecorder, v interface{}) {
	t.Helper()

	if err := json.Unmarshal(resp.Body.Bytes(), v); err != nil {
		t.Fatalf("Failed to parse JSON response: %v\nBody: %s", err, resp.Body.String())
	}
}

// AssertStatusCode checks if the response has the expected status code
func AssertStatusCode(t *testing.T, resp *httptest.ResponseRecorder, expected int) {
	t.Helper()

	if resp.Code != expected {
		t.Errorf("Expected status code %d, got %d\nBody: %s",
			expected, resp.Code, resp.Body.String())
	}
}

// AssertJSONContentType checks if the response has JSON content type
func AssertJSONContentType(t *testing.T, resp *httptest.ResponseRecorder) {
	t.Helper()

	contentType := resp.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

// AssertCookie checks if a cookie exists and optionally validates its value
func AssertCookie(t *testing.T, resp *httptest.ResponseRecorder, name string, expectedValue ...string) *http.Cookie {
	t.Helper()

	cookies := resp.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			if len(expectedValue) > 0 && cookie.Value != expectedValue[0] {
				t.Errorf("Cookie %s: expected value '%s', got '%s'",
					name, expectedValue[0], cookie.Value)
			}
			return cookie
		}
	}

	t.Errorf("Cookie %s not found in response", name)
	return nil
}

// SetCookie adds a cookie to an HTTP request
func SetCookie(req *http.Request, name, value string) {
	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
	})
}

// SetAuthHeader sets the Authorization header with a Bearer token
func SetAuthHeader(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
}
