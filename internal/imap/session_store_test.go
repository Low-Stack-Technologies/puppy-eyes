package imap

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

const getEmailsInMailboxQuery = `-- name: GetEmailsInMailbox :many
SELECT e.id, e.sender, e.recipients, e.body, e.created_at, em.flags, em.uid
FROM emails e
JOIN email_mailbox em ON e.id = em.email_id
WHERE em.mailbox_id = $1
ORDER BY em.uid ASC
`

const updateEmailFlagsQuery = `-- name: UpdateEmailFlags :exec
UPDATE email_mailbox
SET flags = $3
WHERE email_id = $1 AND mailbox_id = $2
`

const deleteEmailFromMailboxQuery = `-- name: DeleteEmailFromMailbox :exec
DELETE FROM email_mailbox
WHERE email_id = $1 AND mailbox_id = $2
`

const deleteOrphanEmailsQuery = `-- name: DeleteOrphanEmails :exec
DELETE FROM emails e
WHERE NOT EXISTS (
    SELECT 1 FROM email_mailbox em WHERE em.email_id = e.id
)
`

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }
func (c *bufferConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *bufferConn) Close() error                { return nil }
func (c *bufferConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *bufferConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *bufferConn) SetDeadline(time.Time) error { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *bufferConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

type fakeRow struct{}

func (r fakeRow) Scan(...interface{}) error {
	return errors.New("not implemented")
}

type fakeRows struct {
	mu   sync.Mutex
	data [][]any
	idx  int
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Next() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.idx >= len(r.data) {
		return false
	}
	r.idx++
	return true
}
func (r *fakeRows) Scan(dest ...interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.idx == 0 || r.idx > len(r.data) {
		return errors.New("scan out of bounds")
	}
	row := r.data[r.idx-1]
	if len(dest) != len(row) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *pgtype.UUID:
			*d = row[i].(pgtype.UUID)
		case *string:
			*d = row[i].(string)
		case *[]string:
			*d = row[i].([]string)
		case *pgtype.Timestamptz:
			*d = row[i].(pgtype.Timestamptz)
		case *int64:
			*d = row[i].(int64)
		default:
			return errors.New("unsupported scan type")
		}
	}
	return nil
}
func (r *fakeRows) Values() ([]interface{}, error) { return nil, nil }
func (r *fakeRows) RawValues() [][]byte            { return nil }
func (r *fakeRows) Conn() *pgx.Conn                { return nil }

type fakeDB struct {
	mu sync.Mutex

	mailboxEmails map[pgtype.UUID][]db.GetEmailsInMailboxRow

	updateCalls []db.UpdateEmailFlagsParams
	deleteCalls []db.DeleteEmailFromMailboxParams
	pruneCalled bool
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch sql {
	case updateEmailFlagsQuery:
		f.updateCalls = append(f.updateCalls, db.UpdateEmailFlagsParams{
			EmailID:   args[0].(pgtype.UUID),
			MailboxID: args[1].(pgtype.UUID),
			Flags:     args[2].([]string),
		})
		return pgconn.CommandTag{}, nil
	case deleteEmailFromMailboxQuery:
		f.deleteCalls = append(f.deleteCalls, db.DeleteEmailFromMailboxParams{
			EmailID:   args[0].(pgtype.UUID),
			MailboxID: args[1].(pgtype.UUID),
		})
		return pgconn.CommandTag{}, nil
	case deleteOrphanEmailsQuery:
		f.pruneCalled = true
		return pgconn.CommandTag{}, nil
	default:
		return pgconn.CommandTag{}, nil
	}
}

func (f *fakeDB) Query(_ context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if sql != getEmailsInMailboxQuery {
		return &fakeRows{}, nil
	}
	mailboxID := args[0].(pgtype.UUID)
	f.mu.Lock()
	emails := f.mailboxEmails[mailboxID]
	f.mu.Unlock()

	var rows [][]any
	for _, e := range emails {
		rows = append(rows, []any{
			e.ID,
			e.Sender,
			e.Recipients,
			e.Body,
			e.CreatedAt,
			e.Flags,
			e.Uid,
		})
	}
	return &fakeRows{data: rows}, nil
}

func (f *fakeDB) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return fakeRow{}
}

func newUUID(b byte) pgtype.UUID {
	var buf [16]byte
	buf[0] = b
	return pgtype.UUID{Bytes: buf, Valid: true}
}

func TestHandleStoreUpdatesFlags(t *testing.T) {
	originalQ := db.Q
	defer func() { db.Q = originalQ }()

	mailboxID := newUUID(0x10)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	fake := &fakeDB{
		mailboxEmails: map[pgtype.UUID][]db.GetEmailsInMailboxRow{
			mailboxID: {
				{ID: newUUID(0x01), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{}, Uid: 10},
				{ID: newUUID(0x02), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{"\\Seen"}, Uid: 20},
			},
		},
	}
	db.Q = db.New(fake)

	conn := &bufferConn{}
	session := &imapSession{
		conn:                conn,
		authenticatedUserID: pgtype.UUID{Valid: true},
		selectedMailbox:     &db.GetMailboxByNameForUserRow{ID: mailboxID},
	}

	session.handleStore("A1", false, []string{"1:2", "+FLAGS.SILENT", "(\\Seen Custom)"})

	if bytes.Contains(conn.Bytes(), []byte("FETCH")) {
		t.Fatalf("unexpected FETCH response for silent STORE: %s", conn.String())
	}
	if !bytes.Contains(conn.Bytes(), []byte("A1 OK Store completed")) {
		t.Fatalf("missing OK response: %s", conn.String())
	}
	if len(fake.updateCalls) != 2 {
		t.Fatalf("expected 2 flag updates, got %d", len(fake.updateCalls))
	}
}

func TestHandleStoreUIDTargets(t *testing.T) {
	originalQ := db.Q
	defer func() { db.Q = originalQ }()

	mailboxID := newUUID(0x11)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	fake := &fakeDB{
		mailboxEmails: map[pgtype.UUID][]db.GetEmailsInMailboxRow{
			mailboxID: {
				{ID: newUUID(0x03), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{}, Uid: 10},
				{ID: newUUID(0x04), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{}, Uid: 20},
			},
		},
	}
	db.Q = db.New(fake)

	conn := &bufferConn{}
	session := &imapSession{
		conn:                conn,
		authenticatedUserID: pgtype.UUID{Valid: true},
		selectedMailbox:     &db.GetMailboxByNameForUserRow{ID: mailboxID},
	}

	session.handleStore("A2", true, []string{"20", "+FLAGS", "(\\Seen)"})

	if len(fake.updateCalls) != 1 {
		t.Fatalf("expected 1 flag update, got %d", len(fake.updateCalls))
	}
	if fake.updateCalls[0].EmailID != newUUID(0x04) {
		t.Fatalf("expected UID 20 to be updated")
	}
}

func TestHandleExpungeRemovesDeleted(t *testing.T) {
	originalQ := db.Q
	defer func() { db.Q = originalQ }()

	mailboxID := newUUID(0x12)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	fake := &fakeDB{
		mailboxEmails: map[pgtype.UUID][]db.GetEmailsInMailboxRow{
			mailboxID: {
				{ID: newUUID(0x05), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{"\\Deleted"}, Uid: 10},
				{ID: newUUID(0x06), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{}, Uid: 20},
				{ID: newUUID(0x07), Sender: "a", Recipients: []string{"b"}, Body: "body", CreatedAt: now, Flags: []string{"\\Deleted"}, Uid: 30},
			},
		},
	}
	db.Q = db.New(fake)

	conn := &bufferConn{}
	session := &imapSession{
		conn:                conn,
		authenticatedUserID: pgtype.UUID{Valid: true},
		selectedMailbox:     &db.GetMailboxByNameForUserRow{ID: mailboxID},
	}

	session.handleExpunge("A3")

	output := conn.String()
	if !bytes.Contains([]byte(output), []byte("* 3 EXPUNGE")) || !bytes.Contains([]byte(output), []byte("* 1 EXPUNGE")) {
		t.Fatalf("expected expunge responses in output: %s", output)
	}
	if bytes.Contains([]byte(output), []byte("* 2 EXPUNGE")) {
		t.Fatalf("unexpected expunge for non-deleted message: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("A3 OK Expunge completed")) {
		t.Fatalf("missing OK response: %s", output)
	}
	if len(fake.deleteCalls) != 2 {
		t.Fatalf("expected 2 delete calls, got %d", len(fake.deleteCalls))
	}
	if !fake.pruneCalled {
		t.Fatalf("expected orphan prune to be called")
	}
}
