package smtp

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/imap"
)

// ReceiveEmail processes an incoming email from another server.
// It assumes that domain and recipient verification has already been performed during RCPT TO.
// If successful, it stores the email in the database.
func ReceiveEmail(ctx context.Context, sender string, recipients []string, body string, spfPass, dkimPass, dmarcPass bool) error {
	for _, recipient := range recipients {
		// 1. Find the recipients addresses
		recipientAddresses, err := db.Q.GetAddressFromEmailAddress(ctx, strings.Trim(recipient, "<>"))
		if err != nil {
			return fmt.Errorf("failed to find recipient address: %w", err)
		}

		// 2. Save the email to the database
		emailID, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
			Sender:     sender,
			Recipients: []string{recipient},
			Body:       body,
			SpfPass:    pgtype.Bool{Bool: spfPass, Valid: true},
			DkimPass:   pgtype.Bool{Bool: dkimPass, Valid: true},
			DmarcPass:  pgtype.Bool{Bool: dmarcPass, Valid: true},
		})
		if err != nil {
			return fmt.Errorf("failed to save incoming email: %w", err)
		}

		// 3. Find the inbox mailbox
		inboxMailbox, err := db.Q.GetMailboxOfTypeForAddress(ctx, db.GetMailboxOfTypeForAddressParams{
			Column1:   db.MailboxTypeINBOX,
			AddressID: recipientAddresses.ID,
		})
		if err != nil {
			return fmt.Errorf("failed to find inbox mailbox: %w", err)
		}

		// 4. Add the email to the inbox mailbox
		err = db.Q.AssociateEmailToMailbox(ctx, db.AssociateEmailToMailboxParams{
			EmailID:   emailID,
			MailboxID: inboxMailbox.ID,
			Flags:     []string{"\\Recent"},
		})
		if err != nil {
			return fmt.Errorf("failed to associate email with inbox mailbox: %w", err)
		}

		// Notify IMAP sessions about the new email
		imap.GlobalMailboxUpdateService.Publish(inboxMailbox.ID)
	}

	return nil
}
