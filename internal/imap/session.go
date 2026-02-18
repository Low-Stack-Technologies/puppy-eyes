package imap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

type imapSession struct {
	conn                net.Conn
	reader              *bufio.Reader
	isTLS               bool
	authenticatedUserID pgtype.UUID
	selectedMailbox     *db.GetMailboxByNameForUserRow
}

func (session *imapSession) sendFetchResponse(tag string, isUID bool, data string, args []string) {
	if len(args) < 1 {
		session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing sequence set\r\n", tag)))
		return
	}
	seqSet := args[0]
	upperData := strings.ToUpper(data)
	emails, _ := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)

	// Simple parser for sequence sets like "1", "1:2", "1:*"
	for i, e := range emails {
		msgNum := i + 1
		uid := msgNum // Mock UID

		target := msgNum
		if isUID {
			target = uid
		}

		shouldSend := false
		if seqSet == "*" || seqSet == "1:*" {
			shouldSend = true
		} else if strings.Contains(seqSet, ":") {
			parts := strings.Split(seqSet, ":")
			if len(parts) == 2 {
				start := 0
				fmt.Sscanf(parts[0], "%d", &start)
				if parts[1] == "*" {
					if target >= start {
						shouldSend = true
					}
				} else {
					end := 0
					fmt.Sscanf(parts[1], "%d", &end)
					if target >= start && target <= end {
						shouldSend = true
					}
				}
			}
		} else {
			val := 0
			fmt.Sscanf(seqSet, "%d", &val)
			if target == val {
				shouldSend = true
			}
		}

		if !shouldSend {
			continue
		}

		var items []string

		// Only include items that were requested or are part of standard macros
		// UID
		if strings.Contains(upperData, "UID") || isUID || strings.Contains(upperData, "ALL") || strings.Contains(upperData, "FAST") || strings.Contains(upperData, "FULL") {
			items = append(items, fmt.Sprintf("UID %d", uid))
		}

		// FLAGS
		if strings.Contains(upperData, "FLAGS") || strings.Contains(upperData, "ALL") || strings.Contains(upperData, "FAST") || strings.Contains(upperData, "FULL") {
			items = append(items, fmt.Sprintf("FLAGS %s", formatIMAPFlags(e.Flags)))
		}

		// INTERNALDATE
		if strings.Contains(upperData, "INTERNALDATE") || strings.Contains(upperData, "FULL") {
			// RFC3501 date-time: "01-Jan-2026 15:04:05 -0700" (day is fixed-width with space if < 10)
			internalDate := e.CreatedAt.Time.Format("_2-Jan-2006 15:04:05 -0700")
			items = append(items, fmt.Sprintf("INTERNALDATE %s", quoteIMAP(internalDate)))
		}

		// RFC822.SIZE
		if strings.Contains(upperData, "RFC822.SIZE") || strings.Contains(upperData, "ALL") || strings.Contains(upperData, "FAST") || strings.Contains(upperData, "FULL") {
			items = append(items, fmt.Sprintf("RFC822.SIZE %d", len(e.Body)))
		}

		// ENVELOPE
		if strings.Contains(upperData, "ENVELOPE") || strings.Contains(upperData, "ALL") || strings.Contains(upperData, "FULL") {
			// Standard RFC 2822 date
			envelopeDate := getHeader(e.Body, "Date")
			if envelopeDate == "" {
				envelopeDate = e.CreatedAt.Time.Format("Mon, 02 Jan 2006 15:04:05 -0700")
			}

			subject := getHeader(e.Body, "Subject")
			messageID := getHeader(e.Body, "Message-ID")
			inReplyTo := getHeader(e.Body, "In-Reply-To")

			fromList := formatIMAPAddressList([]string{e.Sender})
			toList := formatIMAPAddressList(e.Recipients)

			// ENVELOPE (date subject from sender reply-to to cc bcc in-reply-to message-id)
			envelope := fmt.Sprintf("(%s %s %s %s %s %s NIL NIL %s %s)",
				quoteIMAP(envelopeDate), quoteIMAP(subject), fromList, fromList, fromList, toList,
				quoteIMAP(inReplyTo), quoteIMAP(messageID))
			items = append(items, fmt.Sprintf("ENVELOPE %s", envelope))
		}

		var sb strings.Builder
		fmt.Fprintf(&sb, "* %d FETCH (", msgNum)
		sb.WriteString(strings.Join(items, " "))

		// BODY[] or RFC822 or BODY.PEEK
		if strings.Contains(upperData, "BODY") || strings.Contains(upperData, "RFC822") {
			if len(items) > 0 {
				sb.WriteString(" ")
			}

			// Check if specifically requesting Header Fields
			if idx := strings.Index(upperData, "HEADER.FIELDS ("); idx != -1 {
				sub := data[idx+len("HEADER.FIELDS ("):]
				endIdx := strings.Index(sub, ")")
				if endIdx != -1 {
					fieldsStr := sub[:endIdx]
					fields := strings.Fields(fieldsStr)
					headerContent := extractHeaders(e.Body, fields)
					// Respond with the specific requested structure (e.g., BODY[HEADER.FIELDS (Subject Date)] {size})
					requestedTag := "BODY[HEADER.FIELDS (" + fieldsStr + ")]"
					fmt.Fprintf(&sb, "%s {%d}\r\n%s", requestedTag, len(headerContent), headerContent)
				}
			} else {
				// Fallback to full body
				fmt.Fprintf(&sb, "BODY[] {%d}\r\n%s", len(e.Body), e.Body)
			}
		}

		sb.WriteString(")\r\n")
		session.conn.Write([]byte(sb.String()))
	}
	okMsg := "Fetch completed"
	if isUID {
		okMsg = "UID Fetch completed"
	}
	session.conn.Write([]byte(fmt.Sprintf("%s OK %s\r\n", tag, okMsg)))
}

func (session *imapSession) handleStore(tag string, isUID bool, args []string) {
	if session.selectedMailbox == nil {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Select a mailbox first\r\n", tag)))
		return
	}
	if len(args) < 3 {
		session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing arguments for STORE\r\n", tag)))
		return
	}

	seqSet := args[0]
	item := strings.ToUpper(args[1])
	flagsPart := args[2]

	// Parse flags from "( \Seen \Answered )" or " \Seen"
	flagsPart = strings.Trim(flagsPart, "()")
	newFlags := strings.Fields(flagsPart)

	silent := strings.HasSuffix(item, ".SILENT")
	op := "SET"
	if strings.HasPrefix(item, "+") {
		op = "ADD"
	} else if strings.HasPrefix(item, "-") {
		op = "REMOVE"
	}

	emails, _ := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)

	for i, e := range emails {
		msgNum := i + 1
		uid := msgNum // Mock UID

		target := msgNum
		if isUID {
			target = uid
		}

		// Reuse the logic for sequence sets
		shouldUpdate := false
		if seqSet == "*" || seqSet == "1:*" {
			shouldUpdate = true
		} else if strings.Contains(seqSet, ":") {
			parts := strings.Split(seqSet, ":")
			if len(parts) == 2 {
				start := 0
				fmt.Sscanf(parts[0], "%d", &start)
				if parts[1] == "*" {
					if target >= start {
						shouldUpdate = true
					}
				} else {
					end := 0
					fmt.Sscanf(parts[1], "%d", &end)
					if target >= start && target <= end {
						shouldUpdate = true
					}
				}
			}
		} else {
			val := 0
			fmt.Sscanf(seqSet, "%d", &val)
			if target == val {
				shouldUpdate = true
			}
		}

		if !shouldUpdate {
			continue
		}

		// Calculate updated flags
		var finalFlags []string
		currentFlagsMap := make(map[string]bool)
		for _, f := range e.Flags {
			currentFlagsMap[f] = true
		}

		switch op {
		case "SET":
			finalFlags = newFlags
		case "ADD":
			for _, f := range newFlags {
				currentFlagsMap[f] = true
			}
			for f := range currentFlagsMap {
				finalFlags = append(finalFlags, f)
			}
		case "REMOVE":
			for _, f := range newFlags {
				delete(currentFlagsMap, f)
			}
			for f := range currentFlagsMap {
				finalFlags = append(finalFlags, f)
			}
		}

		// Update Database
		db.Q.UpdateEmailFlags(context.Background(), db.UpdateEmailFlagsParams{
			EmailID:   e.ID,
			MailboxID: session.selectedMailbox.ID,
			Flags:     finalFlags,
		})

		// Send untagged response if not silent
		if !silent {
			res := fmt.Sprintf("* %d FETCH (FLAGS (%s)", msgNum, strings.Join(finalFlags, " "))
			if isUID {
				res += fmt.Sprintf(" UID %d", uid)
			}
			res += ")\r\n"
			session.conn.Write([]byte(res))
		}
	}

	okMsg := "Store completed"
	if isUID {
		okMsg = "UID Store completed"
	}
	session.conn.Write([]byte(fmt.Sprintf("%s OK %s\r\n", tag, okMsg)))
}
