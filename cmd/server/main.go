package main

import (
	"context"
	"log"
	"sync"

	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	webhttp "github.com/low-stack-technologies/puppy-eyes/internal/http"
	"github.com/low-stack-technologies/puppy-eyes/internal/imap"
	"github.com/low-stack-technologies/puppy-eyes/internal/smtp"
	"github.com/low-stack-technologies/puppy-eyes/internal/utils/env"
)

func main() {
	ctx := context.Background()
	if err := env.LoadDotEnv(".env"); err != nil {
		log.Printf("failed to load .env: %v", err)
	}

	connStr := "postgresql://puppy:pup@localhost:5432/pup?sslmode=disable"
	db.Connect(ctx, connStr)

	var wg sync.WaitGroup
	wg.Add(5)

	go smtp.StartWorker(ctx, &wg)
	go smtp.StartListening(&wg)
	go imap.StartListening(&wg)
	go smtp.StartDMARCReporter(ctx, &wg)
	go webhttp.StartListening(&wg)

	wg.Wait()
}
