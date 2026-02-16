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

// SendEmail handles sending an email from an authenticated user.
// It saves the email to the database and then attempts to relay it to the recipients' mail servers.
func SendEmail(ctx context.Context, userID pgtype.UUID, sender string, recipients []string, body string) error {
	// 1. Save the email to the database
	_, err := db.Q.CreateEmail(ctx, db.CreateEmailParams{
		Sender:            sender,
		Recipients:        recipients,
		Body:              body,
		AuthenticatedUser: userID,
		SpfPass:           pgtype.Bool{Valid: false},
		DmarcPass:         pgtype.Bool{Valid: false},
		DkimPass:          pgtype.Bool{Valid: false},
	})
	if err != nil {
		return fmt.Errorf("failed to save outgoing email: %w", err)
	}

	// 2. Group recipients by domain to minimize connections
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

	// 3. For each domain, lookup MX records and try to send
	for domain, domainRecipients := range domainGroups {
		hosts, err := dns.LookupMX(domain)
		if err != nil {
			log.Printf("Failed to lookup MX for domain %s: %v", domain, err)
			continue
		}

		if len(hosts) == 0 {
			// Fallback to A record if no MX records found (as per RFC 5321)
			hosts = []string{domain}
		}

		success := false
		for _, host := range hosts {
			addr := net.JoinHostPort(host, "25")
			log.Printf("Attempting to send to %s via %s", domain, addr)

			err := smtp.SendMail(addr, nil, senderAddr, domainRecipients, []byte(body))
			if err != nil {
				log.Printf("Failed to send to %s via %s: %v", domain, host, err)
				continue
			}

			log.Printf("Successfully sent email to %s via %s", domain, host)
			success = true
			break
		}

		if !success {
			log.Printf("Failed to send email to any MX for domain %s", domain)
		}
	}

	return nil
}
