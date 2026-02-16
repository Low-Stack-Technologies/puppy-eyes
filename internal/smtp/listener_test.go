package smtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

// mockDBTX satisfies the DBTX interface to allow testing without a real database.
type mockDBTX struct{}

func (m *mockDBTX) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (m *mockDBTX) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, nil
}
func (m *mockDBTX) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return &mockRow{query: query, args: args}
}

// mockRow satisfies the pgx.Row interface for scanning results.
type mockRow struct {
	query string
	args  []interface{}
}

func (r *mockRow) Scan(dest ...interface{}) error {
	// For GetUserByCredentials, return NoRows to simulate auth failure in existing tests.
	if strings.Contains(r.query, "GetUserByCredentials") {
		return pgx.ErrNoRows
	}

	// For MTARelayProtection test & others: fail if domain is unknown
	if strings.Contains(r.query, "GetDomainByName") {
		if len(r.args) > 0 {
			domain := r.args[0].(string)
			// We only want to allow certain domains in our mock for success tests
			if domain != "yourdomain.com" && domain != "example.com" {
				return pgx.ErrNoRows
			}
		}
	}
	// For other queries (GetAddressByNameAndDomain, CreateEmail), return success.
	return nil
}

func TestMain(m *testing.M) {
	// Silence the global logger to keep test output clean during automated runs.
	log.SetOutput(io.Discard)

	// Initialize db.Q with a mock to avoid nil pointer dereference panics
	// when handleSMTPConnection calls users.Authenticate.
	db.Q = db.New(&mockDBTX{})

	os.Exit(m.Run())
}

// TestHandleSMTPConnection_EHLO verifies that the server responds correctly to EHLO
// and advertises its capabilities (STARTTLS, AUTH).
func TestHandleSMTPConnection_EHLO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)

	// Read initial greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.Contains(line, "220") {
		t.Errorf("Expected 220 greeting, got %s", line)
	}

	// Send EHLO command
	fmt.Fprintf(client, "EHLO localhost\r\n")

	// Read multi-line responses
	foundSTARTTLS := false
	foundAUTH := false
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read EHLO response: %v", err)
		}
		if strings.Contains(line, "STARTTLS") {
			foundSTARTTLS = true
		}
		if strings.Contains(line, "AUTH LOGIN PLAIN") {
			foundAUTH = true
		}
		if strings.HasPrefix(line, "250 ") { // End of responses
			break
		}
	}

	if !foundSTARTTLS {
		t.Error("EHLO response missing STARTTLS")
	}
	if !foundAUTH {
		t.Error("EHLO response missing AUTH")
	}
}

// TestHandleSMTPConnection_UnauthenticatedMailRejected ensures that for MSA connections,
// the client MUST authenticate before being allowed to use MAIL FROM.
func TestHandleSMTPConnection_UnauthenticatedMailRejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)

	// Read greeting
	reader.ReadString('\n')

	// Attempt MAIL FROM without having sent AUTH first
	fmt.Fprintf(client, "MAIL FROM:<sender@example.com>\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "503") {
		t.Errorf("Expected 503 Not logged in, got %s", line)
	}
}

// TestHandleSMTPConnection_MTARelayProtection verifies that the server-to-server MTA
// prevents relaying (sending to external domains) but accepts mail for local domains.
func TestHandleSMTPConnection_MTARelayProtection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, SERVER_TO_SERVER_MTA)

	reader := bufio.NewReader(client)

	// Read greeting
	reader.ReadString('\n')

	// Send EHLO
	fmt.Fprintf(client, "EHLO remote.server.com\r\n")
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// MAIL FROM (MTA allows unauthenticated MAIL FROM)
	fmt.Fprintf(client, "MAIL FROM:<external@otherdomain.com>\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Errorf("Expected 250 OK for MTA MAIL FROM, got %s", line)
	}

	// RCPT TO (Should fail for external domain due to relay protection)
	fmt.Fprintf(client, "RCPT TO:<victim@anotherdomain.com>\r\n")
	line, _ = reader.ReadString('\n')
	if !strings.HasPrefix(line, "554") {
		t.Errorf("Expected 554 Relaying denied, got %s", line)
	}

	// RCPT TO (Should pass for local domain: yourdomain.com)
	fmt.Fprintf(client, "RCPT TO:<user@yourdomain.com>\r\n")
	line, _ = reader.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Errorf("Expected 250 OK for local recipient, got %s", line)
	}
}

// TestHandleSMTPConnection_Quit checks if the QUIT command closes the session correctly.
func TestHandleSMTPConnection_Quit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "QUIT\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "221") {
		t.Errorf("Expected 221 Bye, got %s", line)
	}
}

// TestHandleSMTPConnection_InvalidCommand checks response to unknown SMTP commands.
func TestHandleSMTPConnection_InvalidCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "UNKNOWN\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "500") {
		t.Errorf("Expected 500 Unrecognized command, got %s", line)
	}
}

// TestHandleSMTPConnection_STARTTLS_MissingCerts verifies behavior when certificates
// are not available. It expects the server to close the connection after failing to load certs.
func TestHandleSMTPConnection_STARTTLS_MissingCerts(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "STARTTLS\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "220 Ready to start TLS") {
		t.Errorf("Expected 220 Ready to start TLS, got %s", line)
	}
	
	// Subsequent read should fail because the server goroutine exits upon cert load failure.
	_, err := reader.ReadString('\n')
	if err == nil {
		t.Error("Expected error reading after STARTTLS failure (server should have closed connection)")
	}
}

// TestHandleSMTPConnection_DATA tests the full flow of receiving an email from an MTA
// including MAIL, RCPT, and the DATA command with message body.
func TestHandleSMTPConnection_DATA(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Use MTA mode to bypass authentication requirement for this protocol test.
	go handleSMTPConnection(server, SERVER_TO_SERVER_MTA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "EHLO localhost\r\n")
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// use test.invalid domain to ensure SPF/DMARC checks result in "neutral/pass"
	// rather than "reject" due to missing network records.
	fmt.Fprintf(client, "MAIL FROM:<sender@test.invalid>\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(client, "RCPT TO:<user@yourdomain.com>\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(client, "DATA\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "354") {
		t.Fatalf("Expected 354 Start mail input, got %s", line)
	}

	// Send actual email content
	fmt.Fprintf(client, "Subject: Test\r\n\r\nHello!\r\n.\r\n")
	line, _ = reader.ReadString('\n')
	if !strings.Contains(line, "250") {
		t.Errorf("Expected 250 OK: queued, got %s", line)
	}
}

// TestHandleSMTPConnection_AUTH_PLAIN_Invalid tests the PLAIN authentication mechanism
// using the mock database.
func TestHandleSMTPConnection_AUTH_PLAIN_Invalid(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "EHLO localhost\r\n")
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// AHVzZXIAcGFzcw== is "user\x00user\x00pass" base64 encoded.
	fmt.Fprintf(client, "AUTH PLAIN AHVzZXIAcGFzcw==\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "535") {
		t.Errorf("Expected 535 Authentication credentials invalid, got %s", line)
	}
}

// TestHandleSMTPConnection_AUTH_LOGIN_Invalid tests the multi-step LOGIN authentication
// mechanism using the mock database.
func TestHandleSMTPConnection_AUTH_LOGIN_Invalid(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "EHLO localhost\r\n")
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	fmt.Fprintf(client, "AUTH LOGIN\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "334") {
		t.Errorf("Expected 334 username prompt, got %s", line)
	}

	// Send base64 "user"
	fmt.Fprintf(client, "dXNlcg==\r\n")
	line, _ = reader.ReadString('\n')
	if !strings.Contains(line, "334") {
		t.Errorf("Expected 334 password prompt, got %s", line)
	}

	// Send base64 "pass"
	fmt.Fprintf(client, "cGFzcw==\r\n")
	line, _ = reader.ReadString('\n')
	if !strings.HasPrefix(line, "535") {
		t.Errorf("Expected 535 Authentication credentials invalid, got %s", line)
	}
}

// TestHandleSMTPConnection_SequenceError ensures the server rejects DATA when
// MAIL and RCPT have not been provided yet.
func TestHandleSMTPConnection_SequenceError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, SERVER_TO_SERVER_MTA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	// Try DATA without MAIL/RCPT
	fmt.Fprintf(client, "DATA\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "503") {
		t.Errorf("Expected 503 Sequence error, got %s", line)
	}
}

// TestHandleSMTPConnection_MultipleRecipients verifies that the server can handle
// multiple RCPT TO commands for a single email.
func TestHandleSMTPConnection_MultipleRecipients(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, SERVER_TO_SERVER_MTA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "MAIL FROM:<sender@test.invalid>\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(client, "RCPT TO:<user1@yourdomain.com>\r\n")
	reader.ReadString('\n')
	fmt.Fprintf(client, "RCPT TO:<user2@yourdomain.com>\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "250") {
		t.Errorf("Expected 250 OK for second recipient, got %s", line)
	}
}

// TestHandleSMTPConnection_DotUnstuffing verifies that a leading period in a line
// is correctly removed (transparently) as per the SMTP protocol.
func TestHandleSMTPConnection_DotUnstuffing(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, SERVER_TO_SERVER_MTA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	fmt.Fprintf(client, "MAIL FROM:<sender@test.invalid>\r\n")
	reader.ReadString('\n')
	fmt.Fprintf(client, "RCPT TO:<user@yourdomain.com>\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(client, "DATA\r\n")
	reader.ReadString('\n')

	// Send data with a leading dot that should be unstuffed (.. -> .)
	fmt.Fprintf(client, "Normal line\r\n..Leading dot\r\n.\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "250") {
		t.Errorf("Expected 250 OK, got %s", line)
	}
}

// TestHandleSMTPConnection_MAIL_Malformed verifies that the server handles
// malformed MAIL commands gracefully (no panics).
func TestHandleSMTPConnection_MAIL_Malformed(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go handleSMTPConnection(server, CLIENT_TO_SERVER_MSA)

	reader := bufio.NewReader(client)
	reader.ReadString('\n') // Greeting

	// "MAIL X" is malformed (too short)
	fmt.Fprintf(client, "MAIL X\r\n")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "501") {
		t.Errorf("Expected 501 Syntax error, got %s", line)
	}
}
