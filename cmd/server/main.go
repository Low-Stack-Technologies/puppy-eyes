package main

import (
	"context"

	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/smtp"
)

func main() {
	ctx := context.Background()
	connStr := "postgresql://puppy:pup@localhost:5432/pup?sslmode=disable"
	db.Connect(ctx, connStr)

	smtp.StartListening()
}
