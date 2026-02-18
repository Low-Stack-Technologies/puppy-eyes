package smtp

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
)

// StartWorker begins the background process of sending queued emails.
func StartWorker(ctx context.Context, rwg *sync.WaitGroup) {
	defer rwg.Done()

	log.Println("Starting SMTP background worker...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("SMTP background worker stopping...")
			return
		case <-ticker.C:
			processQueue(ctx)
		}
	}
}

func processQueue(ctx context.Context) {
	for {
		// 1. Pick an email from the queue using a transaction
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			log.Printf("Worker: failed to start transaction: %v", err)
			return
		}

		qtx := db.Q.WithTx(tx)
		item, err := qtx.GetNextEmailFromQueue(ctx)
		if err != nil {
			tx.Rollback(ctx)
			// Likely no more items ready to process
			return
		}

		// 2. Mark as processing to ensure other workers (if any) don't pick it up
		err = qtx.MarkEmailAsProcessing(ctx, item.ID)
		if err != nil {
			log.Printf("Worker: failed to mark as processing (ID: %s): %v", item.ID, err)
			tx.Rollback(ctx)
			continue
		}

		// 3. Attempt to relay the email
		log.Printf("Worker: processing email %s (Attempt: %d)", item.ID, item.RetryCount+1)
		err = RelayEmail(ctx, item.Sender, item.Recipients, item.Body)

		if err != nil {
			log.Printf("Worker: failed to relay email %s: %v", item.ID, err)

			retryCount := item.RetryCount + 1
			var nextAttempt pgtype.Timestamptz

			if retryCount < 10 {
				// Exponential backoff: 1m, 2m, 4m, 8m, 16m...
				delay := time.Duration(1<<uint(retryCount)) * time.Minute
				nextAttempt = pgtype.Timestamptz{Time: time.Now().Add(delay), Valid: true}
				log.Printf("Worker: scheduling retry for email %s in %v", item.ID, delay)

				if err = qtx.UpdateQueueStatus(ctx, db.UpdateQueueStatusParams{
					ID:            item.ID,
					Status:        db.EmailStatusFailed,
					RetryCount:    retryCount,
					NextAttemptAt: nextAttempt,
					LastError:     pgtype.Text{String: err.Error(), Valid: true},
				}); err != nil {
					log.Printf("Failed to schedule retry for email %s, because %s", item.ID, err)
					continue
				}
			} else {
				log.Printf("Worker: max retries reached for email %s. Giving up.", item.ID)
				err = qtx.UpdateQueueStatus(ctx, db.UpdateQueueStatusParams{
					ID:            item.ID,
					Status:        db.EmailStatusFailed,
					RetryCount:    retryCount,
					NextAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(168 * time.Hour), Valid: true}, // 1 week
					LastError:     pgtype.Text{String: "Max retries reached: " + err.Error(), Valid: true},
				})
			}
		} else {
			log.Printf("Worker: successfully sent email %s", item.ID)
			err = qtx.MarkEmailAsSent(ctx, item.ID)
		}

		if err != nil {
			log.Printf("Worker: failed to update status for email %s: %v", item.ID, err)
		}

		// Commit the result
		err = tx.Commit(ctx)
		if err != nil {
			log.Printf("Worker: failed to commit transaction for email %s: %v", item.ID, err)
		}
	}
}
