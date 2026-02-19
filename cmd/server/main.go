package main

import (
	"context"
	"sync"

	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/imap"
	"github.com/low-stack-technologies/puppy-eyes/internal/smtp"
)

func main() {
	ctx := context.Background()
	connStr := "postgresql://puppy:pup@localhost:5432/pup?sslmode=disable"
	db.Connect(ctx, connStr)

	var wg sync.WaitGroup
	wg.Add(4)

	go smtp.StartWorker(ctx, &wg)
	go smtp.StartListening(&wg)
	go imap.StartListening(&wg)
	go smtp.StartDMARCReporter(ctx, &wg)

	wg.Wait()
}
