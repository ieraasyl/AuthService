package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/ieraasyl/AuthService/internal/database"
	"github.com/ieraasyl/AuthService/internal/handlers"
	"github.com/ieraasyl/AuthService/internal/middleware"
	"github.com/ieraasyl/AuthService/internal/services"
	"github.com/ieraasyl/AuthService/pkg/cache"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"

	_ "github.com/ieraasyl/AuthService/docs" // Import generated docs
)

// @title           AuthService Authentication Service API
// @version         1.0
// @description     Production-ready authentication service with Google OAuth 2.0, JWT tokens, and session management.
// @description     Features: Multi-device sessions, token blacklisting, rate limiting, geolocation tracking.
//
// @contact.name   API Support
// @contact.email  ieraasyl@example.com
//
// @license.name  MIT
// @license.url   https://github.com/ieraasyl/AuthService/blob/main/LICENSE
//
// @host      localhost:8080
// @BasePath  /
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
//
// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name access_token
// @description JWT access token stored in HttpOnly cookie
func main() {
	// Initialize logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	log.Info().
		Str("env", cfg.Server.Environment).
		Str("port", cfg.Server.Port).
		Msg("Starting auth service")

	// Initialize PostgreSQL
	postgresDB, err := database.NewPostgresDB(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL")
	}
	defer postgresDB.Close()

	// Run migrations
	migrationSQL := `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			google_id VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(255),
			picture_url TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			last_login TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = NOW();
			RETURN NEW;
		END;
		$$ language 'plpgsql';

		DROP TRIGGER IF EXISTS update_users_updated_at ON users;
		CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
			FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
	`
	if err := postgresDB.RunMigrations(context.Background(), migrationSQL); err != nil {
		log.Fatal().Err(err).Msg("Failed to run migrations")
	}

	// Initialize Redis
	redisDB, err := database.NewRedisDB(&cfg.Redis)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer redisDB.Close()

	// Initialize cache
	cacheInstance := cache.NewCache(redisDB.Client())

	// Initialize services
	oauthService := services.NewOAuthService(&cfg.OAuth, postgresDB)
	jwtService := services.NewJWTService(&cfg.JWT, redisDB)
	sessionService := services.NewSessionService(redisDB, cacheInstance, cfg.JWT.RefreshExpiry)

	// Initialize handlers
	isProduction := cfg.Server.Environment == "production"
	authHandler := handlers.NewAuthHandler(oauthService, jwtService, sessionService, postgresDB, isProduction, cfg.Server.FrontendURL)
	healthHandler := handlers.NewHealthHandler(postgresDB, redisDB)

	// Initialize middleware
	rateLimiter := middleware.NewRateLimiter(redisDB, cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.WindowDuration)

	// Create router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Recoverer())
	r.Use(middleware.Logger())
	r.Use(middleware.Metrics())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS(cfg.CORS.AllowedOrigins))
	r.Use(chimiddleware.Compress(5))
	r.Use(chimiddleware.Timeout(60 * time.Second))

	// Health check endpoints
	r.Get("/health", healthHandler.Health)
	r.Get("/ready", healthHandler.Ready)

	// Metrics endpoint
	r.Handle("/metrics", middleware.MetricsHandler())

	// Swagger API documentation
	r.Get("/api/docs/*", httpSwagger.Handler(
		httpSwagger.URL("/api/docs/doc.json"), // The url pointing to API definition
	))

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Auth routes (rate limited)
		r.Route("/auth", func(r chi.Router) {
			// Public endpoints
			r.Group(func(r chi.Router) {
				r.Use(rateLimiter.Limit("auth"))
				r.Get("/google/login", authHandler.GoogleLogin)
				r.Get("/google/callback", authHandler.GoogleCallback)
				r.Post("/refresh", authHandler.RefreshToken)
			})

			// Protected endpoints (require JWT)
			r.Group(func(r chi.Router) {
				r.Use(middleware.JWTAuth(jwtService))
				r.Get("/me", authHandler.Me)
				r.Post("/logout", authHandler.Logout)
				r.Get("/sessions", authHandler.ListSessions)
				r.Delete("/sessions/{id}", authHandler.RevokeSession)
				r.Post("/sessions/revoke-others", authHandler.RevokeOtherSessions)
			})
		})
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info().Str("addr", server.Addr).Msg("Server started")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Wait for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Info().Msg("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server stopped gracefully")
}
