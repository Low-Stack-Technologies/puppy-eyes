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
	// 1. Add it to the emails table.
	_, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
		Sender:     sender,
		Recipients: recipients,
		Body:       body,
		SpfPass:    pgtype.Bool{Bool: spfPass, Valid: true},
		DmarcPass:  pgtype.Bool{Bool: dmarcPass, Valid: true},
		DkimPass:   pgtype.Bool{Valid: false}, // Not yet implemented
	})
	if err != nil {
		return fmt.Errorf("failed to save email: %w", err)
	}

	// 2. Add the email to the sent mailbox
	// TODO: Implement this

	return nil
}
