package smtp

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

// ReceiveEmail processes an incoming email from another server.
// It assumes that domain and recipient verification has already been performed during RCPT TO.
// If successful, it stores the email in the database.
func ReceiveEmail(ctx context.Context, sender string, recipients []string, body string, spfPass, dmarcPass bool) error {
	// 3. Add it to the emails table without any authenticated_user.
	_, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
		Sender:            sender,
		Recipients:        recipients,
		Body:              body,
		AuthenticatedUser: pgtype.UUID{Valid: false},
		SpfPass:           pgtype.Bool{Bool: spfPass, Valid: true},
		DmarcPass:         pgtype.Bool{Bool: dmarcPass, Valid: true},
		DkimPass:          pgtype.Bool{Valid: false}, // Not yet implemented
	})
	if err != nil {
		return fmt.Errorf("failed to save email: %w", err)
	}

	return nil
}
