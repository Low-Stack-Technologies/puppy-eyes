package users

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

func Authenticate(ctx context.Context, username, password string) (pgtype.UUID, error) {
	id, err := db.Q.GetUserByCredentials(ctx, db.GetUserByCredentialsParams{
		Username: username,
		Password: password,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("authentication failed: %w", err)
	}
	return id, nil
}
