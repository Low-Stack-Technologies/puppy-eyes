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

	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/users"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/tcp"
)

const IMAP_PORT = 143
const IMAP_TLS_PORT = 993

func handleIMAPConnection(conn net.Conn, isTLS bool) {
	session := &imapSession{
		conn:   conn,
		reader: bufio.NewReader(conn),
		isTLS:  isTLS,
		updates: make(chan struct{}, 1), // Buffered channel for updates
	}
	defer session.conn.Close()

	// 1. Greeting
	session.conn.Write([]byte(fmt.Sprintf("* OK [%s] IMAP4rev1 Service Ready\r\n", session.getCapabilities())))

	// 2. Command loop
	for {
		data, err := tcp.ReadData(session.reader)
		if err != nil {
			log.Printf("IMAP read error: %v", err)
			return
		}

		parts := parseIMAPLine(data)
		if len(parts) == 0 {
			continue
		}

		tag := parts[0]
		var cmd string
		var args []string
		if len(parts) > 1 {
			cmd = strings.ToUpper(parts[1])
			args = parts[2:]
		}

		switch cmd {
		case "CAPABILITY":
			session.conn.Write([]byte("* CAPABILITY " + session.getCapabilities() + "\r\n"))
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
				var payload string
				if len(args) > 1 {
					payload = args[1]
				} else {
					session.conn.Write([]byte("+ \r\n"))
					var err error
					payload, err = tcp.ReadData(session.reader)
					if err != nil {
						// Log the error for debugging purposes.
						log.Printf("Error reading AUTHENTICATE PLAIN payload: %v", err)
						return
					}
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
			} else if subCmd == "STORE" {
				session.handleStore(tag, true, args[1:])
			} else {
				session.conn.Write([]byte(fmt.Sprintf("%s BAD Unsupported UID sub-command\r\n", tag)))
			}

		case "STORE":
			session.handleStore(tag, false, args)

		case "EXPUNGE":
			session.conn.Write([]byte(fmt.Sprintf("%s OK Expunge completed\r\n", tag)))

		case "ID":
			// RFC 2971 ID command
			session.conn.Write([]byte("* ID (\"name\" \"puppy-eyes\" \"version\" \"0.1.0\")\r\n"))
			session.conn.Write([]byte(fmt.Sprintf("%s OK ID completed\r\n", tag)))

		case "IDLE":
			if !session.authenticatedUserID.Valid || session.selectedMailbox == nil {
				session.conn.Write([]byte(fmt.Sprintf("%s NO Authenticate and select a mailbox first\r\n", tag)))
				continue
			}

			session.conn.Write([]byte("+ idling\r\n"))

			idleCtx, cancelIdle := context.WithCancel(context.Background())
			defer cancelIdle() // Ensure cancelIdle is called if we exit early

			// Goroutine to send unsolicited updates
			go func() {
				for {
					select {
					case <-idleCtx.Done():
						return // Stop monitoring when IDLE is terminated
					case <-session.updates:
						// An update occurred, send untagged responses
						// Re-fetch email count to ensure it's up-to-date
						emails, err := db.Q.GetEmailsInMailbox(context.Background(), session.selectedMailbox.ID)
						if err != nil {
							log.Printf("Error getting emails for IDLE update: %v", err)
							continue
						}
						// Sending untagged responses
						session.conn.Write([]byte(fmt.Sprintf("* %d EXISTS\r\n", len(emails))))
						session.conn.Write([]byte("* 0 RECENT\r\n")) // For simplicity, always 0 RECENT for now
					}
				}
			}()

			// Wait for DONE from the client
			for {
				data, err := tcp.ReadData(session.reader)
				if err != nil {
					log.Printf("IMAP IDLE read error: %v", err)
					return // Terminate connection on read error
				}
				if strings.ToUpper(strings.TrimSpace(data)) == "DONE" {
					break // Exit IDLE mode
				}
				// If we receive anything else, it's a protocol violation, terminate IDLE
				// and potentially the connection depending on strictness.
				// For now, just terminate IDLE.
				log.Printf("IMAP IDLE received unexpected command: %s", data)
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
