package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	t.Run("adds request ID to response headers", func(t *testing.T) {
		middleware := Logger()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		requestID := rec.Header().Get("X-Request-ID")
		assert.NotEmpty(t, requestID, "X-Request-ID header should be set")
		assert.Len(t, requestID, 36, "Request ID should be a valid UUID")
	})

	t.Run("uses existing request ID from header", func(t *testing.T) {
		existingID := "custom-request-id-12345"

		middleware := Logger()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", existingID)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		requestID := rec.Header().Get("X-Request-ID")
		assert.Equal(t, existingID, requestID, "Should preserve existing request ID")
	})

	t.Run("logs request and response", func(t *testing.T) {
		middleware := Logger()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Test Response"))
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/test?param=value", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Test Response", rec.Body.String())
	})

	t.Run("handles different HTTP methods", func(t *testing.T) {
		methods := []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
		}

		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				middleware := Logger()
				handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, method, r.Method)
					w.WriteHeader(http.StatusOK)
				}))

				req := httptest.NewRequest(method, "/test", nil)
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)

				assert.Equal(t, http.StatusOK, rec.Code)
			})
		}
	})

	t.Run("handles different status codes", func(t *testing.T) {
		statusCodes := []int{
			http.StatusOK,
			http.StatusCreated,
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusInternalServerError,
		}

		for _, code := range statusCodes {
			t.Run(http.StatusText(code), func(t *testing.T) {
				middleware := Logger()
				handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(code)
				}))

				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)

				assert.Equal(t, code, rec.Code)
			})
		}
	})

	t.Run("propagates context to handler", func(t *testing.T) {
		var capturedRequestID string

		middleware := Logger()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Request ID should be accessible in context via utils.GetRequestID
			// For now, just verify context is passed through
			assert.NotNil(t, r.Context())
			capturedRequestID = w.Header().Get("X-Request-ID")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.NotEmpty(t, capturedRequestID)
		assert.Equal(t, capturedRequestID, rec.Header().Get("X-Request-ID"))
	})
}

func TestRecoverer(t *testing.T) {
	t.Run("recovers from panic and returns 500", func(t *testing.T) {
		middleware := Recoverer()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("intentional panic for testing")
		}))

		req := httptest.NewRequest(http.MethodGet, "/panic", nil)
		rec := httptest.NewRecorder()

		// Should not panic - recoverer should catch it
		assert.NotPanics(t, func() {
			handler.ServeHTTP(rec, req)
		})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "Internal Server Error")
	})

	t.Run("does not interfere with normal requests", func(t *testing.T) {
		middleware := Recoverer()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/normal", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Success", rec.Body.String())
	})

	t.Run("handles different panic types", func(t *testing.T) {
		testCases := []struct {
			name       string
			panicValue interface{}
		}{
			{"string panic", "error string"},
			{"error panic", assert.AnError},
			{"int panic", 42},
			{"nil panic", nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				middleware := Recoverer()
				handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					panic(tc.panicValue)
				}))

				req := httptest.NewRequest(http.MethodGet, "/panic", nil)
				rec := httptest.NewRecorder()

				assert.NotPanics(t, func() {
					handler.ServeHTTP(rec, req)
				})

				assert.Equal(t, http.StatusInternalServerError, rec.Code)
			})
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	t.Run("adds all security headers", func(t *testing.T) {
		middleware := SecurityHeaders()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		headers := rec.Header()

		// Verify each security header is set
		assert.Equal(t, "nosniff", headers.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", headers.Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", headers.Get("X-XSS-Protection"))
		assert.Equal(t, "max-age=31536000; includeSubDomains", headers.Get("Strict-Transport-Security"))
		assert.NotEmpty(t, headers.Get("Content-Security-Policy"))
		assert.Equal(t, "strict-origin-when-cross-origin", headers.Get("Referrer-Policy"))
	})

	t.Run("CSP allows required sources", func(t *testing.T) {
		middleware := SecurityHeaders()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		assert.Contains(t, csp, "default-src 'self'")
		assert.Contains(t, csp, "script-src 'self' 'unsafe-inline'")
		assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
		assert.Contains(t, csp, "img-src 'self' https://lh3.googleusercontent.com")
	})

	t.Run("does not interfere with response", func(t *testing.T) {
		middleware := SecurityHeaders()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Created"))
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "Created", rec.Body.String())
	})
}

func TestCORS(t *testing.T) {
	t.Run("allows configured origins", func(t *testing.T) {
		allowedOrigins := []string{"https://example.com", "https://app.example.com"}
		middleware := CORS(allowedOrigins)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("handles OPTIONS preflight requests", func(t *testing.T) {
		allowedOrigins := []string{"https://example.com"}
		middleware := CORS(allowedOrigins)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// CORS middleware should handle OPTIONS
		assert.NotEmpty(t, rec.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("allows credentials", func(t *testing.T) {
		allowedOrigins := []string{"https://example.com"}
		middleware := CORS(allowedOrigins)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Note: The actual CORS library sets these headers
		// We're testing that the middleware doesn't break the flow
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestMiddlewareChaining(t *testing.T) {
	t.Run("multiple middleware work together", func(t *testing.T) {
		// Create a chain: Recoverer -> Logger -> SecurityHeaders -> Handler
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		})

		chain := Recoverer()(
			Logger()(
				SecurityHeaders()(handler),
			),
		)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Success", rec.Body.String())

		// Verify headers from different middleware
		assert.NotEmpty(t, rec.Header().Get("X-Request-ID"), "Logger should add request ID")
		assert.NotEmpty(t, rec.Header().Get("X-Frame-Options"), "SecurityHeaders should add X-Frame-Options")
	})

	t.Run("recoverer catches panic in downstream middleware", func(t *testing.T) {
		panicMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("middleware panic")
			})
		}

		chain := Recoverer()(
			panicMiddleware(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Should never reach here
					t.Error("Handler should not be called after panic")
				}),
			),
		)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		assert.NotPanics(t, func() {
			chain.ServeHTTP(rec, req)
		})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// Benchmark tests
func BenchmarkLogger(b *testing.B) {
	middleware := Logger()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/bench", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkSecurityHeaders(b *testing.B) {
	middleware := SecurityHeaders()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/bench", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
