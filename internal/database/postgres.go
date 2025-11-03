// Package database provides database access layers for PostgreSQL and Redis.
// Implements connection management, query operations, and transaction handling
// with automatic retry logic and connection pooling.
//
// PostgreSQL is used for persistent user data with ACID guarantees.
// Redis is used for sessions, caching, and rate limiting with high performance.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/ieraasyl/AuthService/pkg/config"
	"github.com/ieraasyl/AuthService/pkg/utils"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

// TxFunc is a function that runs within a database transaction.
// Used with WithTransaction to ensure atomic operations.
//
// The function receives a *sql.Tx which should be used for all
// database operations within the transaction. The transaction will
// be automatically committed on success or rolled back on error/panic.
type TxFunc func(tx *sql.Tx) error

// Querier is an interface for executing SQL queries.
// Abstracts *sql.DB and *sql.Tx to allow the same query code to work
// both inside and outside transactions.
//
// This enables writing functions that can be used in both contexts:
//
//	func GetUser(ctx context.Context, q Querier, userID uuid.UUID) (*User, error) {
//	    // Works with both db and tx
//	    return q.QueryRowContext(ctx, "SELECT ...", userID)
//	}
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// PostgresDB wraps a PostgreSQL database connection with connection pooling.
// Provides high-level methods for user management and transaction handling.
//
// Features:
//   - Automatic connection retry with exponential backoff
//   - Connection pooling (configurable max connections)
//   - Transaction support with automatic rollback on errors
//   - Panic recovery in transactions
//   - Health check support
type PostgresDB struct {
	db *sql.DB // Underlying connection pool
}

// NewPostgresDB creates a new PostgreSQL connection with automatic retry.
// Implements exponential backoff retry logic to handle transient connection
// failures during startup (e.g., database container not ready yet).
//
// Connection pool settings:
//   - MaxOpenConns: From configuration (default: 25)
//   - MaxIdleConns: Half of MaxOpenConns
//   - ConnMaxLifetime: 1 hour
//
// Retry configuration:
//   - Max attempts: 5
//   - Initial delay: 100ms
//   - Max delay: 3 seconds
//   - Total timeout: 30 seconds
//
// Parameters:
//   - cfg: Database configuration including DSN and connection limits
//
// Returns the connected database or an error if all retries fail.
//
// Example:
//
//	db, err := database.NewPostgresDB(&config.DatabaseConfig{
//	    Host:     "localhost",
//	    Port:     "5432",
//	    User:     "postgres",
//	    Password: "secret",
//	    DBName:   "myapp",
//	    MaxConns: 25,
//	})
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Database connection failed")
//	}
//	defer db.Close()
func NewPostgresDB(cfg *config.DatabaseConfig) (*PostgresDB, error) {
	var db *sql.DB
	var connErr error

	// Retry database connection with exponential backoff
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	retryConfig := utils.DatabaseRetryConfig()
	retryConfig.MaxAttempts = 5
	retryConfig.InitialDelay = 100 * time.Millisecond
	retryConfig.MaxDelay = 3 * time.Second

	err := utils.Retry(ctx, retryConfig, func() error {
		var err error
		db, err = sql.Open("postgres", cfg.DSN())
		if err != nil {
			connErr = err
			log.Warn().Err(err).Msg("Failed to open database connection, retrying...")
			return err
		}

		// Set connection pool settings
		db.SetMaxOpenConns(cfg.MaxConns)
		db.SetMaxIdleConns(cfg.MaxConns / 2)
		db.SetConnMaxLifetime(time.Hour)

		// Verify connection with ping
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pingCancel()

		if err := db.PingContext(pingCtx); err != nil {
			connErr = err
			log.Warn().Err(err).Msg("Failed to ping database, retrying...")
			db.Close() // Clean up failed connection
			return err
		}

		return nil
	})

	if err != nil {
		if connErr != nil {
			return nil, fmt.Errorf("failed to connect to database after retries: %w", connErr)
		}
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Info().Msg("Successfully connected to PostgreSQL")

	return &PostgresDB{db: db}, nil
}

// Close closes the database connection and releases all resources.
// Should be called when shutting down the application, typically
// with defer in main().
//
// Example:
//
//	db, err := database.NewPostgresDB(cfg)
//	if err != nil {
//	    log.Fatal().Err(err).Msg("Failed to connect")
//	}
//	defer db.Close()
func (p *PostgresDB) Close() error {
	return p.db.Close()
}

// Ping checks if the database connection is alive.
// Used by health check endpoints to verify database availability.
//
// Returns an error if the database is unreachable or not responding.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
//	defer cancel()
//	if err := db.Ping(ctx); err != nil {
//	    return "unhealthy", err
//	}
func (p *PostgresDB) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// CreateUser creates a new user or updates if they already exist (upsert).
// Uses ON CONFLICT to handle the case where a user logs in again,
// updating their profile information and last login time.
//
// Upsert behavior:
//   - If google_id doesn't exist: Create new user
//   - If google_id exists: Update email, name, picture, last_login, updated_at
//
// The user ID is auto-generated by the database (UUID).
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - googleID: Google account unique identifier
//   - email: User's email from Google
//   - name: User's display name from Google
//   - pictureURL: Profile picture URL from Google
//
// Returns the created or updated user model.
//
// Example:
//
//	user, err := db.CreateUser(ctx,
//	    "1234567890",               // Google ID
//	    "user@example.com",          // Email
//	    "John Doe",                  // Name
//	    "https://lh3.google...",     // Picture
//	)
func (p *PostgresDB) CreateUser(ctx context.Context, googleID, email, name, pictureURL string) (*models.User, error) {
	query := `
		INSERT INTO users (google_id, email, name, picture_url, last_login)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (google_id) 
		DO UPDATE SET 
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			picture_url = EXCLUDED.picture_url,
			last_login = NOW(),
			updated_at = NOW()
		RETURNING id, google_id, email, name, picture_url, created_at, updated_at, last_login
	`

	var user models.User
	err := p.db.QueryRowContext(ctx, query, googleID, email, name, pictureURL).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	log.Info().
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Msg("User created/updated successfully")

	return &user, nil
}

// GetUserByID retrieves a user by their unique UUID.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: The user's UUID
//
// Returns the user model or an error if not found.
//
// Example:
//
//	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
//	user, err := db.GetUserByID(ctx, userID)
//	if err != nil {
//	    return nil, errors.New("user not found")
//	}
func (p *PostgresDB) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, google_id, email, name, picture_url, created_at, updated_at, last_login
		FROM users
		WHERE id = $1
	`

	var user models.User
	err := p.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by their email address.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - email: The user's email address
//
// Returns the user model or an error if not found.
//
// Example:
//
//	user, err := db.GetUserByEmail(ctx, "user@example.com")
//	if err != nil {
//	    return nil, errors.New("user not found")
//	}
func (p *PostgresDB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, google_id, email, name, picture_url, created_at, updated_at, last_login
		FROM users
		WHERE email = $1
	`

	var user models.User
	err := p.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByGoogleID retrieves a user by their Google account ID.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - googleID: The user's Google account unique identifier
//
// Returns the user model or an error if not found.
//
// Example:
//
//	user, err := db.GetUserByGoogleID(ctx, "1234567890")
//	if err != nil {
//	    return nil, errors.New("user not found")
//	}
func (p *PostgresDB) GetUserByGoogleID(ctx context.Context, googleID string) (*models.User, error) {
	query := `
		SELECT id, google_id, email, name, picture_url, created_at, updated_at, last_login
		FROM users
		WHERE google_id = $1
	`

	var user models.User
	err := p.db.QueryRowContext(ctx, query, googleID).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateLastLogin updates the last login timestamp for a user.
// Also updates the updated_at timestamp.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - userID: The user's UUID
//
// Returns an error if the update fails.
//
// Example:
//
//	if err := db.UpdateLastLogin(ctx, userID); err != nil {
//	    log.Warn().Err(err).Msg("Failed to update last login")
//	}
func (p *PostgresDB) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET last_login = NOW(), updated_at = NOW()
		WHERE id = $1
	`

	_, err := p.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// RunMigrations executes database migrations from SQL string.
// Should be called during application startup to ensure schema is up to date.
//
// The migration SQL should be idempotent (safe to run multiple times)
// using CREATE TABLE IF NOT EXISTS, etc.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - migrationSQL: The SQL migration script to execute
//
// Returns an error if migration fails.
//
// Example:
//
//	migrationSQL := `
//	    CREATE TABLE IF NOT EXISTS users (
//	        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//	        email VARCHAR(255) UNIQUE NOT NULL,
//	        ...
//	    );
//	`
//	if err := db.RunMigrations(ctx, migrationSQL); err != nil {
//	    log.Fatal().Err(err).Msg("Migration failed")
//	}
func (p *PostgresDB) RunMigrations(ctx context.Context, migrationSQL string) error {
	_, err := p.db.ExecContext(ctx, migrationSQL)
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Info().Msg("Database migrations completed successfully")
	return nil
}

// WithTransaction executes a function within a database transaction.
// Automatically handles commit on success and rollback on error or panic.
//
// Transaction guarantees:
//   - ACID properties (Atomicity, Consistency, Isolation, Durability)
//   - Automatic rollback on errors
//   - Panic recovery with rollback
//   - Commit only on successful completion
//
// The function receives a *sql.Tx which should be used for all
// database operations that need to be atomic.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - fn: Function to execute within the transaction
//
// Returns an error if the transaction fails or is rolled back.
//
// Example:
//
//	err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
//	    // Create user
//	    user, err := CreateUserTx(ctx, tx, googleID, email, name, picture)
//	    if err != nil {
//	        return err // Automatic rollback
//	    }
//
//	    // Update related data
//	    if err := UpdateUserMetaTx(ctx, tx, user.ID); err != nil {
//	        return err // Automatic rollback
//	    }
//
//	    return nil // Automatic commit
//	})
func (p *PostgresDB) WithTransaction(ctx context.Context, fn TxFunc) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is closed
	defer func() {
		if r := recover(); r != nil {
			// Panic occurred, rollback and re-panic
			if rbErr := tx.Rollback(); rbErr != nil {
				log.Error().Err(rbErr).Msg("Failed to rollback transaction after panic")
			}
			panic(r)
		}
	}()

	// Execute the function
	if err := fn(tx); err != nil {
		// Function returned error, rollback
		if rbErr := tx.Rollback(); rbErr != nil {
			log.Error().Err(rbErr).Msg("Failed to rollback transaction")
			return fmt.Errorf("transaction error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	// Success, commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithTransactionOptions executes a function within a transaction with custom options.
// Similar to WithTransaction but allows specifying transaction isolation level
// and read-only mode.
//
// Transaction options:
//   - Isolation: sql.LevelDefault, sql.LevelReadCommitted, sql.LevelSerializable, etc.
//   - ReadOnly: true for read-only transactions (better performance)
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - opts: Transaction options (isolation level, read-only flag)
//   - fn: Function to execute within the transaction
//
// Returns an error if the transaction fails or is rolled back.
//
// Example:
//
//	// Read-only transaction with serializable isolation
//	opts := &sql.TxOptions{
//	    Isolation: sql.LevelSerializable,
//	    ReadOnly:  true,
//	}
//	err := db.WithTransactionOptions(ctx, opts, func(tx *sql.Tx) error {
//	    users, err := GetAllUsersTx(ctx, tx)
//	    // ... process read-only data
//	    return nil
//	})
func (p *PostgresDB) WithTransactionOptions(ctx context.Context, opts *sql.TxOptions, fn TxFunc) error {
	tx, err := p.db.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if r := recover(); r != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				log.Error().Err(rbErr).Msg("Failed to rollback transaction after panic")
			}
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			log.Error().Err(rbErr).Msg("Failed to rollback transaction")
			return fmt.Errorf("transaction error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// CreateUserTx creates a user within an existing transaction.
// Use this with WithTransaction when the user creation is part of
// a larger atomic operation.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tx: Active transaction
//   - googleID: Google account unique identifier
//   - email: User's email
//   - name: User's name
//   - pictureURL: Profile picture URL
//
// Returns the created or updated user model.
//
// Example:
//
//	err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
//	    user, err := database.CreateUserTx(ctx, tx, googleID, email, name, picture)
//	    if err != nil {
//	        return err
//	    }
//	    // More operations...
//	    return nil
//	})
func CreateUserTx(ctx context.Context, tx *sql.Tx, googleID, email, name, pictureURL string) (*models.User, error) {
	query := `
		INSERT INTO users (google_id, email, name, picture_url, last_login)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (google_id) 
		DO UPDATE SET 
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			picture_url = EXCLUDED.picture_url,
			last_login = NOW(),
			updated_at = NOW()
		RETURNING id, google_id, email, name, picture_url, created_at, updated_at, last_login
	`

	var user models.User
	err := tx.QueryRowContext(ctx, query, googleID, email, name, pictureURL).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	return &user, nil
}

// UpdateLastLoginTx updates the last login timestamp within a transaction.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tx: Active transaction
//   - userID: The user's UUID
//
// Returns an error if the user is not found or update fails.
//
// Example:
//
//	err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
//	    if err := database.UpdateLastLoginTx(ctx, tx, userID); err != nil {
//	        return err
//	    }
//	    return nil
//	})
func UpdateLastLoginTx(ctx context.Context, tx *sql.Tx, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET last_login = NOW(), updated_at = NOW()
		WHERE id = $1
	`

	result, err := tx.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUserByIDTx retrieves a user by ID within a transaction.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - tx: Active transaction
//   - userID: The user's UUID
//
// Returns the user model or an error if not found.
//
// Example:
//
//	err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
//	    user, err := database.GetUserByIDTx(ctx, tx, userID)
//	    if err != nil {
//	        return err
//	    }
//	    // More operations...
//	    return nil
//	})
func GetUserByIDTx(ctx context.Context, tx *sql.Tx, userID uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, google_id, email, name, picture_url, created_at, updated_at, last_login
		FROM users
		WHERE id = $1
	`

	var user models.User
	err := tx.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.GoogleID,
		&user.Email,
		&user.Name,
		&user.PictureURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}
