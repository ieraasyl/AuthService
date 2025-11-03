package cache

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/ieraasyl/AuthService/internal/models"
	"github.com/rs/zerolog/log"
)

// UserDatabase defines the interface for user database operations
type UserDatabase interface {
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByGoogleID(ctx context.Context, googleID string) (*models.User, error)
	CreateUser(ctx context.Context, googleID, email, name, picture string) (*models.User, error)
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
}

// UserCache provides caching for user data
type UserCache struct {
	cache *Cache
	db    UserDatabase
	ttl   time.Duration
}

// NewUserCache creates a new user cache
func NewUserCache(cache *Cache, db UserDatabase, ttl time.Duration) *UserCache {
	return &UserCache{
		cache: cache,
		db:    db,
		ttl:   ttl,
	}
}

// GetUserByID retrieves a user by ID with caching
func (uc *UserCache) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	key := UserKey(userID)

	err := uc.cache.GetOrSet(ctx, key, uc.ttl, &user, func() (interface{}, error) {
		return uc.db.GetUserByID(ctx, userID)
	})

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email with caching
func (uc *UserCache) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	key := UserByEmailKey(email)

	err := uc.cache.GetOrSet(ctx, key, uc.ttl, &user, func() (interface{}, error) {
		return uc.db.GetUserByEmail(ctx, email)
	})

	if err != nil {
		return nil, err
	}

	// Also cache by user ID for future lookups
	if err := uc.cache.Set(ctx, UserKey(user.ID), &user, uc.ttl); err != nil {
		log.Warn().Err(err).Msg("Failed to cache user by ID")
	}

	return &user, nil
}

// GetUserByGoogleID retrieves a user by Google ID with caching
func (uc *UserCache) GetUserByGoogleID(ctx context.Context, googleID string) (*models.User, error) {
	var user models.User
	key := UserByGoogleIDKey(googleID)

	err := uc.cache.GetOrSet(ctx, key, uc.ttl, &user, func() (interface{}, error) {
		return uc.db.GetUserByGoogleID(ctx, googleID)
	})

	if err != nil {
		return nil, err
	}

	// Also cache by user ID for future lookups
	if err := uc.cache.Set(ctx, UserKey(user.ID), &user, uc.ttl); err != nil {
		log.Warn().Err(err).Msg("Failed to cache user by ID")
	}

	return &user, nil
}

// CreateUser creates a new user and caches it
func (uc *UserCache) CreateUser(ctx context.Context, googleID, email, name, picture string) (*models.User, error) {
	user, err := uc.db.CreateUser(ctx, googleID, email, name, picture)
	if err != nil {
		return nil, err
	}

	// Cache the new user
	if err := uc.cacheUser(ctx, user); err != nil {
		log.Warn().Err(err).Msg("Failed to cache newly created user")
	}

	return user, nil
}

// UpdateLastLogin updates the last login time and invalidates cache
func (uc *UserCache) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	if err := uc.db.UpdateLastLogin(ctx, userID); err != nil {
		return err
	}

	// Invalidate user cache so next read gets fresh data
	if err := uc.InvalidateUser(ctx, userID); err != nil {
		log.Warn().Err(err).Msg("Failed to invalidate user cache")
	}

	return nil
}

// InvalidateUser removes all cached data for a user
func (uc *UserCache) InvalidateUser(ctx context.Context, userID uuid.UUID) error {
	// We can only invalidate the user ID key directly
	// Email and Google ID keys will expire naturally via TTL
	key := UserKey(userID)
	return uc.cache.Delete(ctx, key)
}

// InvalidateAllUsers removes all cached user data (use sparingly)
func (uc *UserCache) InvalidateAllUsers(ctx context.Context) error {
	return uc.cache.DeletePattern(ctx, UserAllPattern())
}

// cacheUser caches a user by ID, email, and Google ID
func (uc *UserCache) cacheUser(ctx context.Context, user *models.User) error {
	// Cache by user ID
	if err := uc.cache.Set(ctx, UserKey(user.ID), user, uc.ttl); err != nil {
		return err
	}

	// Cache by email
	if err := uc.cache.Set(ctx, UserByEmailKey(user.Email), user, uc.ttl); err != nil {
		log.Warn().Err(err).Msg("Failed to cache user by email")
	}

	// Cache by Google ID
	if err := uc.cache.Set(ctx, UserByGoogleIDKey(user.GoogleID), user, uc.ttl); err != nil {
		log.Warn().Err(err).Msg("Failed to cache user by Google ID")
	}

	return nil
}

// WarmupCache pre-loads frequently accessed users into cache
func (uc *UserCache) WarmupCache(ctx context.Context, userIDs []uuid.UUID) error {
	for _, userID := range userIDs {
		user, err := uc.db.GetUserByID(ctx, userID)
		if err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to warmup user cache")
			continue
		}

		if err := uc.cacheUser(ctx, user); err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to cache user during warmup")
		}
	}

	return nil
}
