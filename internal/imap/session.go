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
	updates             chan struct{} // Channel to signal updates for IDLE command
}

func (session *imapSession) getCapabilities() string {
	caps := "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ "
	if session.isTLS {
		caps += "AUTH=PLAIN"
	} else {
		caps += "STARTTLS LOGINDISABLED"
	}
	return caps
}

func (session *imapSession) sendFetchResponse(tag string, isUID bool, data string, args []string) {
	if len(args) < 1 {
		session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing sequence set\r\n", tag)))
		return
	}
	seqSet := args[0]
	upperData := strings.ToUpper(data)
	emails, _ := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)

	maxUID := 0
	for _, e := range emails {
		if int(e.Uid) > maxUID {
			maxUID = int(e.Uid)
		}
	}

	maxTarget := len(emails)
	if isUID {
		maxTarget = maxUID
	}
	targetSet := parseSequenceSet(seqSet, maxTarget)

	for i, e := range emails {
		msgNum := i + 1
		uid := int(e.Uid)

		target := msgNum
		if isUID {
			target = uid
		}

		if !targetSet[target] {
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
			items = append(items, fmt.Sprintf("FLAGS %s", formatIMAPFlags(normalizeFlags(e.Flags))))
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
	if !session.authenticatedUserID.Valid {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
		return
	}
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
	newFlags := normalizeFlags(strings.Fields(flagsPart))

	silent := strings.HasSuffix(item, ".SILENT")
	item = strings.TrimSuffix(item, ".SILENT")
	op := "SET"
	if strings.HasPrefix(item, "+") {
		op = "ADD"
		item = strings.TrimPrefix(item, "+")
	} else if strings.HasPrefix(item, "-") {
		op = "REMOVE"
		item = strings.TrimPrefix(item, "-")
	}
	if item != "FLAGS" {
		session.conn.Write([]byte(fmt.Sprintf("%s BAD Unsupported STORE item\r\n", tag)))
		return
	}

	emails, _ := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)
	maxUID := 0
	for _, e := range emails {
		if int(e.Uid) > maxUID {
			maxUID = int(e.Uid)
		}
	}
	maxTarget := len(emails)
	if isUID {
		maxTarget = maxUID
	}
	targetSet := parseSequenceSet(seqSet, maxTarget)

	for i, e := range emails {
		msgNum := i + 1
		uid := int(e.Uid)

		target := msgNum
		if isUID {
			target = uid
		}

		if !targetSet[target] {
			continue
		}

		// Calculate updated flags
		var finalFlags []string
		currentFlagsMap := make(map[string]bool)
		for _, f := range normalizeFlags(e.Flags) {
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

		finalFlags = normalizeFlags(finalFlags)

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

	GlobalMailboxUpdateService.Publish(session.selectedMailbox.ID)

	okMsg := "Store completed"
	if isUID {
		okMsg = "UID Store completed"
	}
	session.conn.Write([]byte(fmt.Sprintf("%s OK %s\r\n", tag, okMsg)))
}

func (session *imapSession) handleExpunge(tag string) {
	if !session.authenticatedUserID.Valid {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
		return
	}
	if session.selectedMailbox == nil {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Select a mailbox first\r\n", tag)))
		return
	}

	emails, err := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)
	if err != nil {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Failed to expunge mailbox\r\n", tag)))
		return
	}

	type expungeItem struct {
		seq     int
		emailID pgtype.UUID
	}
	var expungeList []expungeItem
	for i, e := range emails {
		if hasFlag(e.Flags, "\\Deleted") {
			expungeList = append(expungeList, expungeItem{
				seq:     i + 1,
				emailID: e.ID,
			})
		}
	}

	for i := len(expungeList) - 1; i >= 0; i-- {
		item := expungeList[i]
		err := db.Q.DeleteEmailFromMailbox(context.Background(), db.DeleteEmailFromMailboxParams{
			EmailID:   item.emailID,
			MailboxID: session.selectedMailbox.ID,
		})
		if err != nil {
			session.conn.Write([]byte(fmt.Sprintf("%s NO Failed to expunge mailbox\r\n", tag)))
			return
		}
		session.conn.Write([]byte(fmt.Sprintf("* %d EXPUNGE\r\n", item.seq)))
	}

	if err := db.Q.DeleteOrphanEmails(context.Background()); err != nil {
		session.conn.Write([]byte(fmt.Sprintf("%s NO Failed to prune mailbox\r\n", tag)))
		return
	}

	GlobalMailboxUpdateService.Publish(session.selectedMailbox.ID)
	session.conn.Write([]byte(fmt.Sprintf("%s OK Expunge completed\r\n", tag)))
}

// subscribeToMailboxUpdates subscribes the current session to updates for its selected mailbox.
func (session *imapSession) subscribeToMailboxUpdates() {
	if session.selectedMailbox != nil {
		GlobalMailboxUpdateService.Subscribe(session.selectedMailbox.ID, session.updates)
	}
}

// unsubscribeFromMailboxUpdates unsubscribes the current session from updates for its previously selected mailbox.
func (session *imapSession) unsubscribeFromMailboxUpdates() {
	if session.selectedMailbox != nil {
		GlobalMailboxUpdateService.Unsubscribe(session.selectedMailbox.ID, session.updates)
	}
}
