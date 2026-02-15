package smtp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/low-stack-technologies/puppy-eyes/internal/utils/tcp"
)

const SMTP_LISTENING_PORT = 587
const SMTP_DOMAIN = "smtp.yourdomain.com"

func handleSMTPConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	isTLS := false
	var authenticatedUser string
	var envelopeFrom string
	var envelopeTo []string

	// 1. Greeting
	conn.Write([]byte(fmt.Sprintf("220 %s ESMTP Service Ready\r\n", SMTP_DOMAIN)))

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
			conn.Write([]byte(fmt.Sprintf("250-%s\r\n", SMTP_DOMAIN)))
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
				authenticatedUser = string(decodedUser)

				// Prompt for Password (ignored for now)
				conn.Write([]byte("334 UGFzc3dvcmQ6\r\n"))
				_, err = tcp.ReadData(reader)
				if err != nil {
					return
				}
				log.Printf("User %s authenticated via LOGIN", authenticatedUser)
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
				if len(creds) >= 2 {
					authenticatedUser = creds[1]
				}
				log.Printf("User %s authenticated via PLAIN", authenticatedUser)
				conn.Write([]byte("235 2.7.0 Authentication successful\r\n"))

			default:
				conn.Write([]byte("504 5.7.4 Unrecognized authentication type\r\n"))
				continue
			}

		case "MAIL":
			if len(parts) < 2 {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			if parts[1][:4] != "FROM" {
				conn.Write([]byte("501 5.5.4 Syntax error in parameters\r\n"))
				continue
			}

			if authenticatedUser == "" {
				conn.Write([]byte("503 5.5.2 Not logged in\r\n"))
				continue
			}

			envelopeFrom = parts[1][5:]
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

			if authenticatedUser == "" {
				conn.Write([]byte("503 5.5.2 Not logged in\r\n"))
				continue
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
				if len(strings.TrimPrefix(line, ".")) == 0 {
					line = line[1:]
				}
				body.WriteString(line)
			}

			log.Printf("Received email data from %s to %v:\n%s", envelopeFrom, envelopeTo, body.String())

			// Reset envelope for the next transaction on the same connection
			envelopeFrom = ""
			envelopeTo = nil
			conn.Write([]byte("250 2.0.0 OK: queued\r\n"))

		case "QUIT":
			conn.Write([]byte("221 Bye\r\n"))
			return

		default:
			conn.Write([]byte("500 5.5.1 Unrecognized command\r\n"))
		}
	}
}

func StartListening() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", SMTP_LISTENING_PORT))
	if err != nil {
		panic(fmt.Errorf("An error occurred while attempting to start the SMTP server: %w", err))
	}

	defer listener.Close()
	log.Printf("SMTP server listening on port %d", SMTP_LISTENING_PORT)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SMTP accept failed: %v", err)
			continue
		}
		log.Printf("SMTP server received connection from %s", conn.RemoteAddr())
		go handleSMTPConnection(conn)
	}
}
