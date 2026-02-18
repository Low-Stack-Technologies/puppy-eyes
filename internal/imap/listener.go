package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/users"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/tcp"
)

const IMAP_PORT = 143
const IMAP_TLS_PORT = 993

type imapSession struct {
	conn                net.Conn
	reader              *bufio.Reader
	isTLS               bool
	authenticatedUserID pgtype.UUID
	selectedMailbox     *db.GetMailboxByNameForUserRow
}

func parseIMAPLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	parenLevel := 0

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			// We keep the quotes in the parts to allow consistent trimming later
			current.WriteByte(c)
		case c == '(' && !inQuote:
			parenLevel++
			current.WriteByte(c)
		case c == ')' && !inQuote:
			parenLevel--
			current.WriteByte(c)
		case c == ' ' && !inQuote && parenLevel == 0:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func formatIMAPAddress(email string) string {
	email = strings.Trim(email, "<>")
	parts := strings.Split(email, "@")
	mailbox := email
	host := ""
	if len(parts) == 2 {
		mailbox = parts[0]
		host = parts[1]
	}
	// (display-name source-route mailbox-name hostname)
	return fmt.Sprintf("(NIL NIL %s %s)", quoteIMAP(mailbox), quoteIMAP(host))
}

func quoteIMAP(s string) string {
	if s == "" {
		return "NIL"
	}
	return fmt.Sprintf("\"%s\"", strings.ReplaceAll(s, "\"", "\\\""))
}

func formatIMAPAddressList(emails []string) string {
	if len(emails) == 0 {
		return "NIL"
	}
	var sb strings.Builder
	sb.WriteString("(")
	for i, email := range emails {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(formatIMAPAddress(email))
	}
	sb.WriteString(")")
	return sb.String()
}

func getHeader(fullBody, field string) string {
	parts := strings.SplitN(fullBody, "\r\n\r\n", 2)
	headerSection := parts[0]
	headerLines := strings.Split(headerSection, "\r\n")
	fieldLower := strings.ToLower(field) + ":"
	for i := 0; i < len(headerLines); i++ {
		line := headerLines[i]
		if strings.HasPrefix(strings.ToLower(line), fieldLower) {
			val := strings.TrimSpace(line[len(fieldLower):])
			// Handle folded lines
			for j := i + 1; j < len(headerLines); j++ {
				if len(headerLines[j]) > 0 && (headerLines[j][0] == ' ' || headerLines[j][0] == '\t') {
					val += " " + strings.TrimSpace(headerLines[j])
					i = j
				} else {
					break
				}
			}
			return val
		}
	}
	return ""
}

func extractHeaders(fullBody string, fields []string) string {
	parts := strings.SplitN(fullBody, "\r\n\r\n", 2)
	headerSection := parts[0]
	headerLines := strings.Split(headerSection, "\r\n")
	var filtered []string
	
	for _, field := range fields {
		fieldLower := strings.ToLower(field) + ":"
		for i := 0; i < len(headerLines); i++ {
			line := headerLines[i]
			if strings.HasPrefix(strings.ToLower(line), fieldLower) {
				filtered = append(filtered, line)
				for j := i + 1; j < len(headerLines); j++ {
					if len(headerLines[j]) > 0 && (headerLines[j][0] == ' ' || headerLines[j][0] == '\t') {
						filtered = append(filtered, headerLines[j])
						i = j
					} else {
						break
					}
				}
			}
		}
	}
	return strings.Join(filtered, "\r\n") + "\r\n\r\n"
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
			items = append(items, "FLAGS (\\Seen)")
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

func handleIMAPConnection(conn net.Conn, isTLS bool) {
	session := &imapSession{
		conn:   conn,
		reader: bufio.NewReader(conn),
		isTLS:  isTLS,
	}
	defer session.conn.Close()

	// 1. Greeting
	capabilities := "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS"
	if !session.isTLS {
		capabilities += " LOGINDISABLED"
	}
	session.conn.Write([]byte(fmt.Sprintf("* OK [%s] IMAP4rev1 Service Ready\r\n", capabilities)))

	// 2. Command loop
	for {
		data, err := tcp.ReadData(session.reader)
		if err != nil {
			log.Printf("IMAP read error: %v", err)
			return
		}

		log.Printf("IMAP client: %s", data)

		parts := parseIMAPLine(data)
		if len(parts) == 0 {
			continue
		}

		tag := parts[0]
		var cmd string
		if len(parts) > 1 {
			cmd = strings.ToUpper(parts[1])
		}

		args := parts[2:]

		switch cmd {
		case "CAPABILITY":
			caps := "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS"
			if !session.isTLS {
				caps += " LOGINDISABLED"
			}
			session.conn.Write([]byte(caps + "\r\n"))
			session.conn.Write([]byte(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag)))

		case "STARTTLS":
			if session.isTLS {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Already in TLS mode\r\n", tag)))
				continue
			}

			session.conn.Write([]byte(fmt.Sprintf("%s OK Begin TLS negotiation now\r\n", tag)))

			cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
			if err != nil {
				log.Printf("Failed to load key pair: %v", err)
				return
			}

			tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
			tlsConn := tls.Server(session.conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}

			session.conn = tlsConn
			session.reader = bufio.NewReader(session.conn)
			session.isTLS = true

		case "LOGIN":
			if len(args) < 2 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing arguments for LOGIN\r\n", tag)))
				continue
			}
			username := strings.Trim(args[0], "\"")
			password := strings.Trim(args[1], "\"")

			userID, err := users.Authenticate(context.Background(), username, password)
			if err != nil {
				log.Printf("Authentication failed for user %s: %v", username, err)
				session.conn.Write([]byte(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag)))
				continue
			}

			session.authenticatedUserID = userID
			session.conn.Write([]byte(fmt.Sprintf("%s OK User logged in\r\n", tag)))

		case "AUTHENTICATE":
			if len(args) < 1 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing auth type\r\n", tag)))
				continue
			}
			authType := strings.ToUpper(args[0])
			if authType == "PLAIN" {
				session.conn.Write([]byte("+ \r\n"))
				payload, err := tcp.ReadData(session.reader)
				if err != nil {
					return
				}
				decoded, err := base64.StdEncoding.DecodeString(payload)
				if err != nil {
					session.conn.Write([]byte(fmt.Sprintf("%s NO Invalid base64\r\n", tag)))
					continue
				}
				creds := strings.Split(string(decoded), "\x00")
				if len(creds) < 3 {
					session.conn.Write([]byte(fmt.Sprintf("%s NO Invalid credentials format\r\n", tag)))
					continue
				}
				username := creds[1]
				password := creds[2]

				userID, err := users.Authenticate(context.Background(), username, password)
				if err != nil {
					log.Printf("Authentication failed for user %s: %v", username, err)
					session.conn.Write([]byte(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag)))
					continue
				}

				session.authenticatedUserID = userID
				session.conn.Write([]byte(fmt.Sprintf("%s OK Success\r\n", tag)))
			} else {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag)))
			}

		case "LIST", "LSUB":
			if !session.authenticatedUserID.Valid {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if len(args) < 2 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing arguments for %s\r\n", tag, cmd)))
				continue
			}
			
			mailbox := strings.Trim(args[1], "\"")
			if mailbox == "" {
				// Delimiter discovery: Return the hierarchy delimiter and a NIL root
				session.conn.Write([]byte(fmt.Sprintf("* %s (\\Noselect) \"/\" \"\"\r\n", cmd)))
				session.conn.Write([]byte(fmt.Sprintf("%s OK %s completed\r\n", tag, cmd)))
				continue
			}

			mailboxes, err := db.Q.GetUserMailboxes(context.Background(), session.authenticatedUserID)
			if err != nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Failed to list mailboxes\r\n", tag)))
				continue
			}

			for _, m := range mailboxes {
				session.conn.Write([]byte(fmt.Sprintf("* %s (\\HasNoChildren) \"/\" \"%s\"\r\n", cmd, m.Name)))
			}
			session.conn.Write([]byte(fmt.Sprintf("%s OK %s completed\r\n", tag, cmd)))

		case "STATUS":
			if !session.authenticatedUserID.Valid {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if len(args) < 2 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing arguments for STATUS\r\n", tag)))
				continue
			}
			mailboxName := strings.Trim(args[0], "\"")
			// Items are often in parentheses like (MESSAGES UNSEEN)
			itemsStr := strings.ToUpper(args[1])

			mailbox, err := db.Q.GetMailboxByNameForUser(context.Background(), db.GetMailboxByNameForUserParams{
				UserID: session.authenticatedUserID,
				Name:   mailboxName,
			})
			if err != nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Mailbox not found\r\n", tag)))
				continue
			}

			emails, _ := db.Q.GetEmailsInMailbox(context.Background(), mailbox.ID)
			
			var statusItems []string
			if strings.Contains(itemsStr, "MESSAGES") {
				statusItems = append(statusItems, fmt.Sprintf("MESSAGES %d", len(emails)))
			}
			if strings.Contains(itemsStr, "RECENT") {
				statusItems = append(statusItems, "RECENT 0")
			}
			if strings.Contains(itemsStr, "UIDNEXT") {
				statusItems = append(statusItems, fmt.Sprintf("UIDNEXT %d", len(emails)+1))
			}
			if strings.Contains(itemsStr, "UIDVALIDITY") {
				statusItems = append(statusItems, "UIDVALIDITY 1")
			}
			if strings.Contains(itemsStr, "UNSEEN") {
				statusItems = append(statusItems, "UNSEEN 0")
			}

			session.conn.Write([]byte(fmt.Sprintf("* STATUS \"%s\" (%s)\r\n", mailboxName, strings.Join(statusItems, " "))))
			session.conn.Write([]byte(fmt.Sprintf("%s OK STATUS completed\r\n", tag)))

		case "CREATE":
			if !session.authenticatedUserID.Valid {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if len(args) < 1 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing mailbox name\r\n", tag)))
				continue
			}
			mailboxName := strings.Trim(args[0], "\"")
			
			// Get the address ID for this user
			addressID, err := db.Q.GetAddressIDForUser(context.Background(), session.authenticatedUserID)
			if err != nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Could not find a valid address for user\r\n", tag)))
				continue
			}

			err = db.Q.CreateMailbox(context.Background(), db.CreateMailboxParams{
				Name:      mailboxName,
				AddressID: addressID,
			})
			if err != nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Folder already exists or cannot be created\r\n", tag)))
				continue
			}
			session.conn.Write([]byte(fmt.Sprintf("%s OK CREATE completed\r\n", tag)))

		case "SELECT":
			if !session.authenticatedUserID.Valid {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate first\r\n", tag)))
				continue
			}
			if len(args) < 1 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing mailbox name\r\n", tag)))
				continue
			}
			mailboxName := strings.Trim(args[0], "\"")
			mailbox, err := db.Q.GetMailboxByNameForUser(context.Background(), db.GetMailboxByNameForUserParams{
				UserID: session.authenticatedUserID,
				Name:   mailboxName,
			})
			if err != nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Mailbox not found\r\n", tag)))
				continue
			}

			session.selectedMailbox = &mailbox
			emails, _ := db.Q.GetEmailsInMailbox(context.Background(), mailbox.ID)

			session.conn.Write([]byte(fmt.Sprintf("* %d EXISTS\r\n", len(emails))))
			session.conn.Write([]byte("* 0 RECENT\r\n"))
			session.conn.Write([]byte("* OK [UIDVALIDITY 1] UIDs valid\r\n"))
			session.conn.Write([]byte("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"))
			session.conn.Write([]byte(fmt.Sprintf("%s OK [READ-WRITE] Select completed\r\n", tag)))

		case "FETCH":
			if session.selectedMailbox == nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Select a mailbox first\r\n", tag)))
				continue
			}
			session.sendFetchResponse(tag, false, data, args)

		case "UID":
			if len(args) < 1 {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Missing UID sub-command\r\n", tag)))
				continue
			}
			subCmd := strings.ToUpper(args[0])
			if subCmd == "FETCH" {
				if session.selectedMailbox == nil {
					session.conn.Write([]byte(fmt.Sprintf("%s NO Select a mailbox first\r\n", tag)))
					continue
				}
				session.sendFetchResponse(tag, true, data, args[1:])
			} else {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Unsupported UID sub-command\r\n", tag)))
			}

		case "STORE":
			log.Println("STORE command received: To be implemented")
			session.conn.Write([]byte(fmt.Sprintf("%s OK Store completed\r\n", tag)))

		case "EXPUNGE":
			log.Println("EXPUNGE command received: To be implemented")
			session.conn.Write([]byte(fmt.Sprintf("%s OK Expunge completed\r\n", tag)))

		case "ID":
			// RFC 2971 ID command
			session.conn.Write([]byte("* ID (\"name\" \"puppy-eyes\" \"version\" \"0.1.0\")\r\n"))
			session.conn.Write([]byte(fmt.Sprintf("%s OK ID completed\r\n", tag)))

		case "IDLE":
			session.conn.Write([]byte("+ idling\r\n"))
			// Wait for DONE
			for {
				idleData, err := tcp.ReadData(session.reader)
				if err != nil {
					return
				}
				if strings.ToUpper(strings.TrimSpace(idleData)) == "DONE" {
					break
				}
				// If we get an empty line, keep waiting
				if idleData == "" {
					continue
				}
				// Any other data from the client technically violates IDLE but we should handle it
				break
			}
			session.conn.Write([]byte(fmt.Sprintf("%s OK Idle terminated\r\n", tag)))

		case "LOGOUT":
			session.conn.Write([]byte("* BYE IMAP4rev1 server terminating connection\r\n"))
			session.conn.Write([]byte(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag)))
			return

		case "NOOP":
			session.conn.Write([]byte(fmt.Sprintf("%s OK NOOP completed\r\n", tag)))

		default:
			log.Printf("IMAP data: %s", data)
			session.conn.Write([]byte(fmt.Sprintf("%s BAD Unknown command %s\r\n", tag, cmd)))
		}
	}
}

func listenOnPort(wg *sync.WaitGroup, port int, isImplicitTLS bool) {
	defer wg.Done()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(fmt.Errorf("An error occurred while attempting to start the IMAP server: %w", err))
	}

	defer listener.Close()
	log.Printf("IMAP server listening on port %d (TLS: %v)", port, isImplicitTLS)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("IMAP accept failed: %v", err)
			continue
		}

		go func(c net.Conn) {
			log.Printf("IMAP server received connection from %s on port %d", c.RemoteAddr(), port)
			if isImplicitTLS {
				cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
				if err != nil {
					log.Printf("Failed to load key pair for implicit TLS: %v", err)
					c.Close()
					return
				}

				tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
				tlsConn := tls.Server(c, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					log.Printf("Implicit TLS handshake failed: %v", err)
					c.Close()
					return
				}
				c = tlsConn
			}
			handleIMAPConnection(c, isImplicitTLS)
		}(conn)
	}
}

func StartListening(rwg *sync.WaitGroup) {
	defer rwg.Done()

	var wg sync.WaitGroup
	wg.Add(2)

	go listenOnPort(&wg, IMAP_PORT, false)
	go listenOnPort(&wg, IMAP_TLS_PORT, true)
	wg.Wait()
}
