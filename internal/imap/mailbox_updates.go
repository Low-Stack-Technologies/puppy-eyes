package imap

import (
	"log"
	"sync"

	"github.com/jackc/pgx/v5/pgtype"
)

// MailboxUpdateService manages subscriptions and publishing of mailbox updates.
type MailboxUpdateService struct {
	mu          sync.RWMutex
	subscribers map[pgtype.UUID][]chan struct{} // MailboxID -> list of channels to notify
}

// Global instance of the MailboxUpdateService
var GlobalMailboxUpdateService = NewMailboxUpdateService()

func NewMailboxUpdateService() *MailboxUpdateService {
	return &MailboxUpdateService{
		subscribers: make(map[pgtype.UUID][]chan struct{}),
	}
}

// Subscribe adds a channel to receive updates for a specific mailbox.
func (s *MailboxUpdateService) Subscribe(mailboxID pgtype.UUID, updateChan chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers[mailboxID] = append(s.subscribers[mailboxID], updateChan)
	log.Printf("Subscribed session to mailbox %s updates", mailboxID)
}

// Unsubscribe removes a channel from receiving updates for a specific mailbox.
func (s *MailboxUpdateService) Unsubscribe(mailboxID pgtype.UUID, updateChan chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if channels, ok := s.subscribers[mailboxID]; ok {
		for i, ch := range channels {
			if ch == updateChan {
				s.subscribers[mailboxID] = append(channels[:i], channels[i+1:]...)
				log.Printf("Unsubscribed session from mailbox %s updates", mailboxID)
				// If no more subscribers, clean up the map entry
				if len(s.subscribers[mailboxID]) == 0 {
					delete(s.subscribers, mailboxID)
				}
				return
			}
		}
	}
}

// Publish sends an update signal to all subscribed channels for a mailbox.
func (s *MailboxUpdateService) Publish(mailboxID pgtype.UUID) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if channels, ok := s.subscribers[mailboxID]; ok {
		log.Printf("Publishing update for mailbox %s to %d subscribers", mailboxID, len(channels))
		for _, ch := range channels {
			select {
			case ch <- struct{}{}:
			default:
				// Non-blocking send: if the channel is full,
				// it means the subscriber is not ready or an update is already pending.
			}
		}
	}
}
