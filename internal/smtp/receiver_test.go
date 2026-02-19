package smtp

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

func TestReceiveEmail_SaveError(t *testing.T) {
	// Setup a mock that returns ErrNoRows for everything (simulating a database failure on insert)
	oldQ := db.Q
	defer func() { db.Q = oldQ }()
	db.Q = db.New(&mockDBTX_AlwaysFail{})

	err := ReceiveEmail(context.Background(), "sender@example.com", []string{"user@example.com"}, "body", true, true, true)
	if err == nil {
		t.Error("Expected error when saving email fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to find recipient address") {
		t.Errorf("Expected 'failed to find recipient address', got '%v'", err)
	}
}

type mockDBTX_AlwaysFail struct{}

func (m *mockDBTX_AlwaysFail) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (m *mockDBTX_AlwaysFail) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, nil
}
func (m *mockDBTX_AlwaysFail) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return &mockRow_AlwaysFail{}
}

type mockRow_AlwaysFail struct{}

func (r *mockRow_AlwaysFail) Scan(dest ...interface{}) error {
	return pgx.ErrNoRows
}
