package smtp

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
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/dns"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/tcp"
)

type SMTP_CONNECTION_TYPE = int

const (
	SERVER_TO_SERVER_MTA SMTP_CONNECTION_TYPE = iota
	CLIENT_TO_SERVER_MSA
	CLIENT_TO_SERVER_LEGACY
)

const SERVER_TO_SERVER_MTA_PORT = 25
const CLIENT_TO_SERVER_MSA_PORT = 587
const CLIENT_TO_SERVER_LEGACY_PORT = 465
const SERVER_IDENTITY = "smtp.puppy-eyes.test"

func handleSMTPConnection(conn net.Conn, connectionType SMTP_CONNECTION_TYPE) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	isTLS := false
	var authenticatedUserID pgtype.UUID
	var envelopeFrom string
	var envelopeTo []string
	var spfPass bool

	// 1. Greeting
	conn.Write([]byte(fmt.Sprintf("220 %s ESMTP Service Ready\r\n", SERVER_IDENTITY)))

	// 2. Command loop
	for {
		data, err := tcp.ReadData(reader)
		if err != nil {
			log.Printf("SMTP read error: %v", err)
			return
		}

		parts := strings.Fields(data)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "EHLO":
			conn.Write([]byte(fmt.Sprintf("250-%s\r\n", SERVER_IDENTITY)))
			if !isTLS {
				conn.Write([]byte("250-STARTTLS\r\n"))
			}
			conn.Write([]byte("250-AUTH LOGIN PLAIN\r\n"))
			conn.Write([]byte("250 8BITMIME\r\n"))

		case "STARTTLS":
			if isTLS {
				conn.Write([]byte("502 5.5.1 Already in TLS mode\r\n"))
				continue
			}
			conn.Write([]byte("220 Ready to start TLS\r\n"))

			cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
			if err != nil {
				log.Printf("Failed to load key pair: %v", err)
				return
			}

			tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}

			conn = tlsConn
			reader = bufio.NewReader(conn)
			isTLS = true

		case "AUTH":
			if len(parts) < 2 {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			authType := strings.ToUpper(parts[1])
			switch authType {
			case "LOGIN":
				// Prompt for Username
				conn.Write([]byte("334 VXNlcm5hbWU6\r\n"))
				userB64, err := tcp.ReadData(reader)
				if err != nil {
					return
				}
				decodedUser, _ := base64.StdEncoding.DecodeString(userB64)
				username := string(decodedUser)

				// Prompt for Password
				conn.Write([]byte("334 UGFzc3dvcmQ6\r\n"))
				passB64, err := tcp.ReadData(reader)
				if err != nil {
					return
				}
				decodedPass, _ := base64.StdEncoding.DecodeString(passB64)
				password := string(decodedPass)

				userID, err := users.Authenticate(context.Background(), username, password)
				if err != nil {
					log.Printf("Authentication failed for user %s: %v", username, err)
					conn.Write([]byte("535 5.7.8 Authentication credentials invalid\r\n"))
					continue
				}

				authenticatedUserID = userID
				log.Printf("User %s (ID: %s) authenticated via LOGIN", username, fmt.Sprintf("%x-%x-%x-%x-%x", userID.Bytes[0:4], userID.Bytes[4:6], userID.Bytes[6:8], userID.Bytes[8:10], userID.Bytes[10:16]))
				conn.Write([]byte("235 2.7.0 Authentication successful\r\n"))

			case "PLAIN":
				var payload string
				if len(parts) > 2 {
					payload = parts[2]
				} else {
					conn.Write([]byte("334 \r\n"))
					payload, err = tcp.ReadData(reader)
					if err != nil {
						return
					}
				}
				decoded, _ := base64.StdEncoding.DecodeString(payload)
				creds := strings.Split(string(decoded), "\x00")
				if len(creds) < 3 {
					conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
					continue
				}
				username := creds[1]
				password := creds[2]

				userID, err := users.Authenticate(context.Background(), username, password)
				if err != nil {
					log.Printf("Authentication failed for user %s: %v", username, err)
					conn.Write([]byte("535 5.7.8 Authentication credentials invalid\r\n"))
					continue
				}

				authenticatedUserID = userID
				log.Printf("User %s (ID: %s) authenticated via PLAIN", username, fmt.Sprintf("%x-%x-%x-%x-%x", userID.Bytes[0:4], userID.Bytes[4:6], userID.Bytes[6:8], userID.Bytes[8:10], userID.Bytes[10:16]))
				conn.Write([]byte("235 2.7.0 Authentication successful\r\n"))

			default:
				conn.Write([]byte("504 5.7.4 Unrecognized authentication type\r\n"))
				continue
			}

		case "MAIL":
			if len(parts) < 2 || len(parts[1]) < 4 || strings.ToUpper(parts[1][:4]) != "FROM" {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			if connectionType != SERVER_TO_SERVER_MTA && !authenticatedUserID.Valid {
				conn.Write([]byte("503 5.5.2 Not logged in\r\n"))
				continue
			}

			// Set the envelop from address and trim for later use
			envelopeFrom = parts[1][5:]
			addr := strings.Trim(envelopeFrom, "<>")
			idx := strings.LastIndex(addr, "@")
			if idx == -1 {
				conn.Write([]byte("550 5.7.1 Invalid sender domain\r\n"))
				envelopeFrom = ""
				continue
			}

			// If authenticated, verify the user owns this address
			if authenticatedUserID.Valid {
				// Get the address from
				address, err := db.Q.GetAddressFromEmailAddress(context.Background(), addr)
				if err != nil {
					log.Printf("User %s tried to send from unauthorized address: %s", authenticatedUserID, addr)
					conn.Write([]byte("550 5.7.1 Sender address rejected: not owned by user\r\n"))
					envelopeFrom = ""
					continue
				}

				// Check if authenticated user has access to the address
				hasAccess, err := db.Q.UserHasAccessToAddress(context.Background(), db.UserHasAccessToAddressParams{
					ID:     address.ID,
					UserID: authenticatedUserID,
				})
				if err != nil || !hasAccess {
					log.Printf("User %s tried to send from unauthorized address: %s", authenticatedUserID, addr)
					conn.Write([]byte("550 5.7.1 Sender address rejected: not owned by user\r\n"))
					envelopeFrom = ""
					continue
				}
			}

			// Perform SPF check for incoming server-to-server mail
			if connectionType == SERVER_TO_SERVER_MTA {
				domainPart := addr[idx+1:]
				remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

				var err error
				spfPass, err = dns.VerifySPF(remoteIP, domainPart)
				if err != nil || !spfPass {
					log.Printf("SPF validation failed for domain %s from IP %s", domainPart, remoteIP)
				}
			}
			conn.Write([]byte("250 OK\r\n"))

		case "RCPT":
			if len(parts) < 2 {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			if parts[1][:2] != "TO" {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			if connectionType != SERVER_TO_SERVER_MTA && !authenticatedUserID.Valid {
				conn.Write([]byte("503 5.5.2 Not logged in\r\n"))
				continue
			}

			// Relay Protection & Recipient Validation:
			// 1. If authenticated, allow relaying to any domain.
			// 2. If unauthenticated (MTA), only allow our local domains and valid users.
			if !authenticatedUserID.Valid && connectionType == SERVER_TO_SERVER_MTA {
				addr := strings.Trim(parts[1][3:], "<>")
				idx := strings.LastIndex(addr, "@")
				if idx == -1 {
					conn.Write([]byte("501 5.1.3 Bad recipient address syntax\r\n"))
					continue
				}
				name := addr[:idx]
				recipientDomain := addr[idx+1:]

				// Verify domain exists in our DB
				domain, err := db.Q.GetDomainByName(context.Background(), recipientDomain)
				if err != nil {
					conn.Write([]byte("554 5.7.1 Relaying denied\r\n"))
					continue
				}

				// Verify address exists in our DB
				_, err = db.Q.GetAddressByNameAndDomain(context.Background(), db.GetAddressByNameAndDomainParams{
					Name:   name,
					Domain: domain.ID,
				})
				if err != nil {
					conn.Write([]byte("550 5.1.1 User unknown\r\n"))
					continue
				}
			}

			envelopeTo = append(envelopeTo, parts[1][3:])
			conn.Write([]byte("250 OK\r\n"))

		case "DATA":
			if envelopeFrom == "" || len(envelopeTo) == 0 {
				conn.Write([]byte("503 5.5.1 Error: need MAIL and RCPT first\r\n"))
				continue
			}

			// Notify the client to start sending the message body
			conn.Write([]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))

			var body strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("SMTP data read error: %v", err)
					return
				}

				// The termination sequence is a line containing only a period "."
				trimmed := strings.TrimRight(line, "\r\n")
				if trimmed == "." {
					break
				}

				// Dot-unstuffing: If a line starts with a period, the first period is removed.
				if strings.HasPrefix(line, ".") {
					line = line[1:]
				}
				body.WriteString(line)
			}

			// Perform DMARC check before accepting the data
			if connectionType == SERVER_TO_SERVER_MTA {
				fromAddr := strings.Trim(envelopeFrom, "<>")
				idx := strings.LastIndex(fromAddr, "@")
				if idx == -1 {
					conn.Write([]byte("550 5.7.1 Invalid sender domain\r\n"))
					continue
				}
				fromDomain := fromAddr[idx+1:]
				dmarcPass, policy, _ := dns.VerifyDMARC(fromDomain, spfPass)

				// Reject if DMARC fails and policy is 'reject' or 'quarantine'
				if !dmarcPass && (policy == "reject" || policy == "quarantine") {
					conn.Write([]byte(fmt.Sprintf("550 5.7.1 DMARC policy violation (%s)\r\n", policy)))
					envelopeFrom = ""
					envelopeTo = nil
					spfPass = false
					continue
				}

				err := ReceiveEmail(context.Background(), envelopeFrom, envelopeTo, body.String(), spfPass, dmarcPass)
				if err != nil {
					log.Printf("Failed to process incoming email: %v", err)
					conn.Write([]byte(fmt.Sprintf("550 5.1.1 %v\r\n", err)))
					envelopeFrom = ""
					envelopeTo = nil
					spfPass = false
					continue
				}
			} else if authenticatedUserID.Valid {
				err := SendEmail(context.Background(), authenticatedUserID, envelopeFrom, envelopeTo, body.String())
				if err != nil {
					log.Printf("Failed to send outgoing email: %v", err)
					conn.Write([]byte(fmt.Sprintf("550 5.1.1 %v\r\n", err)))
					envelopeFrom = ""
					envelopeTo = nil
					spfPass = false
					continue
				}
			}

			log.Printf("Received email data from %s to %v:\n%s", envelopeFrom, envelopeTo, body.String())

			// Reset envelope for the next transaction on the same connection
			envelopeFrom = ""
			envelopeTo = nil
			spfPass = false
			conn.Write([]byte("250 2.0.0 OK: queued\r\n"))

		case "QUIT":
			conn.Write([]byte("221 Bye\r\n"))
			return

		default:
			conn.Write([]byte("500 5.5.1 Unrecognized command\r\n"))
		}
	}
}

func listenOnPort(wg *sync.WaitGroup, port int, connectionType SMTP_CONNECTION_TYPE) {
	// Handle the wait group
	defer wg.Done()

	// Listen on the specified port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(fmt.Errorf("An error occurred while attempting to start the SMTP server: %w", err))
	}

	defer listener.Close()
	log.Printf("SMTP server listening on port %d", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SMTP accept failed: %v", err)
			continue
		}
		log.Printf("SMTP server received connection from %s", conn.RemoteAddr())
		go handleSMTPConnection(conn, connectionType)
	}
}

func StartListening(rwg *sync.WaitGroup) {
	defer rwg.Done()

	var wg sync.WaitGroup
	wg.Add(3)

	go listenOnPort(&wg, SERVER_TO_SERVER_MTA_PORT, SERVER_TO_SERVER_MTA)
	go listenOnPort(&wg, CLIENT_TO_SERVER_MSA_PORT, CLIENT_TO_SERVER_MSA)
	go listenOnPort(&wg, CLIENT_TO_SERVER_LEGACY_PORT, CLIENT_TO_SERVER_LEGACY)
	wg.Wait()
}
