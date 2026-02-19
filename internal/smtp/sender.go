package smtp

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/dns"
)

// SendEmail handles enqueuing an email from an authenticated user.
func SendEmail(ctx context.Context, userID pgtype.UUID, sender string, recipients []string, body string) error {
	// 1. Find the sender address
	log.Printf("Sender: %s", sender)
	senderAddr, err := db.Q.GetAddressFromEmailAddress(ctx, strings.Trim(sender, "<>"))
	if err != nil {
		return fmt.Errorf("failed to find sender address: %w", err)
	}

	// DKIM sign outbound message before queuing
	signedBody, err := SignDKIM(body, strings.SplitN(strings.Trim(sender, "<>"), "@", 2)[1])
	if err != nil {
		return fmt.Errorf("failed to DKIM sign outgoing email: %w", err)
	}

	// 2. Save the email to the database
	emailID, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
		Sender:     sender,
		Recipients: recipients,
		Body:       signedBody,
		SpfPass:    pgtype.Bool{Valid: false},
		DmarcPass:  pgtype.Bool{Valid: false},
		DkimPass:   pgtype.Bool{Valid: false},
	})
	if err != nil {
		return fmt.Errorf("failed to save outgoing email: %w", err)
	}

	// 3. Find the sent mailbox
	sentMailbox, err := db.Q.GetMailboxOfTypeForAddress(ctx, db.GetMailboxOfTypeForAddressParams{
		Column1:   db.MailboxTypeSENT,
		AddressID: senderAddr.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to find sent mailbox: %w", err)
	}

	// 4. Add the email to the sent mailbox
	uid, err := db.Q.AllocateMailboxUID(ctx, sentMailbox.ID)
	if err != nil {
		return fmt.Errorf("failed to allocate mailbox uid: %w", err)
	}

	err = db.Q.AssociateEmailToMailbox(ctx, db.AssociateEmailToMailboxParams{
		EmailID:   emailID,
		MailboxID: sentMailbox.ID,
		Flags:     []string{"\\Seen"},
		Uid:       int64(uid),
	})
	if err != nil {
		return fmt.Errorf("failed to associate email with sent mailbox: %w", err)
	}

	// 3. Enqueue the email
	_, err = db.Q.EnqueueEmail(ctx, emailID)
	if err != nil {
		return fmt.Errorf("failed to enqueue email: %w", err)
	}

	log.Printf("Email from %s enqueued (ID: %s)", sender, emailID)
	return nil
}

// RelayEmail attempts to send an email to its recipients by looking up MX records.
// This is used by the background worker.
func RelayEmail(ctx context.Context, sender string, recipients []string, body string) error {
	// 1. Group recipients by domain to minimize connections
	domainGroups := make(map[string][]string)
	for _, recipient := range recipients {
		addr := strings.Trim(recipient, "<>")
		idx := strings.LastIndex(addr, "@")
		if idx == -1 {
			log.Printf("Invalid recipient address: %s", recipient)
			continue
		}
		domain := addr[idx+1:]
		domainGroups[domain] = append(domainGroups[domain], addr)
	}

	senderAddr := strings.Trim(sender, "<>")
	var lastErr error

	// 2. For each domain, lookup MX records and try to send
	for domain, domainRecipients := range domainGroups {
		hosts, err := dns.LookupMX(domain)
		if err != nil {
			log.Printf("Failed to lookup MX for domain %s: %v", domain, err)
			lastErr = err
			continue
		}

		if len(hosts) == 0 {
			// Fallback to A record if no MX records found (as per RFC 5321)
			hosts = []string{domain}
		}

		success := false
		for _, host := range hosts {
			addr := net.JoinHostPort(host, "25")
			log.Printf("Attempting to relay to %s via %s", domain, addr)

			err := smtp.SendMail(addr, nil, senderAddr, domainRecipients, []byte(body))
			if err != nil {
				log.Printf("Failed to relay to %s via %s: %v", domain, host, err)
				lastErr = err
				continue
			}

			log.Printf("Successfully relayed email to %s via %s", domain, host)
			success = true
			break
		}

		if !success {
			return fmt.Errorf("failed to relay to domain %s: %w", domain, lastErr)
		}
	}

	return nil
}
