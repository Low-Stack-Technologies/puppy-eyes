package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func Authenticate(ctx context.Context, username, password string) (pgtype.UUID, error) {
	legacyID, legacyErr := db.Q.GetUserByCredentials(ctx, db.GetUserByCredentialsParams{
		Username: username,
		Password: password,
	})
	if legacyErr == nil {
		return legacyID, nil
	}

	user, err := db.Q.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pgtype.UUID{}, fmt.Errorf("authentication failed: invalid credentials")
		}
		return pgtype.UUID{}, fmt.Errorf("authentication failed: %w", err)
	}

	// Prefer secure hash verification when available.
	if user.PasswordHash.Valid && user.PasswordHash.String != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(password)); err != nil {
			return pgtype.UUID{}, fmt.Errorf("authentication failed: invalid credentials")
		}
		return user.ID, nil
	}

	// Legacy plaintext fallback with opportunistic migration to hash.
	if user.Password != password {
		return pgtype.UUID{}, fmt.Errorf("authentication failed: invalid credentials")
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err == nil {
		_ = db.Q.SetUserPasswordHash(ctx, db.SetUserPasswordHashParams{
			ID: user.ID,
			PasswordHash: pgtype.Text{
				String: string(hashBytes),
				Valid:  true,
			},
		})
	}

	return user.ID, nil
}
