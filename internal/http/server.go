package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/low-stack-technologies/puppy-eyes/internal/db"
	"github.com/low-stack-technologies/puppy-eyes/internal/imap"
	peSMTP "github.com/low-stack-technologies/puppy-eyes/internal/smtp"
	"github.com/low-stack-technologies/puppy-eyes/internal/users"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/websocket"
)

const (
	defaultHTTPSAddr        = ":443"
	defaultHTTPRedirectAddr = ":80"
	defaultTLSCertPath      = "certs/tls/server.crt"
	defaultTLSKeyPath       = "certs/tls/server.key"
	sessionCookieName       = "pe_session"
	sessionTTL              = 24 * time.Hour
)

type principalKey struct{}

type Principal struct {
	SessionID       pgtype.UUID
	UserID          pgtype.UUID
	Username        string
	IsAdmin         bool
	ActiveAddressID pgtype.UUID
}

type Server struct {
	mux      *http.ServeMux
	wsHub    *WSHub
	staticFS http.Handler
}

func StartListening(wg *sync.WaitGroup) {
	defer wg.Done()

	srv := NewServer()
	httpsAddr := strings.TrimSpace(os.Getenv("HTTPS_ADDR"))
	if httpsAddr == "" {
		httpsAddr = strings.TrimSpace(os.Getenv("HTTP_ADDR"))
	}
	if httpsAddr == "" {
		httpsAddr = defaultHTTPSAddr
	}

	httpRedirectAddr := strings.TrimSpace(os.Getenv("HTTP_REDIRECT_ADDR"))
	if httpRedirectAddr == "" {
		httpRedirectAddr = defaultHTTPRedirectAddr
	}

	httpsServer := &http.Server{
		Addr:              httpsAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	redirectServer := &http.Server{
		Addr: httpRedirectAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + httpsRedirectHost(r.Host) + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := EnsureBootstrapAdmin(context.Background()); err != nil {
		log.Printf("bootstrap admin setup failed: %v", err)
	}

	go func() {
		log.Printf("HTTP redirect server listening on %s", httpRedirectAddr)
		if err := redirectServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP redirect server failed: %v", err)
		}
	}()

	log.Printf("HTTPS server listening on %s", httpsAddr)
	if err := httpsServer.ListenAndServeTLS(tlsCertPath(), tlsKeyPath()); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}

func httpsRedirectHost(host string) string {
	if host == "" {
		return host
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "80" {
			return h
		}
		return host
	}

	return strings.TrimSuffix(host, ":80")
}

func NewServer() *Server {
	s := &Server{mux: http.NewServeMux(), wsHub: NewWSHub()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	s.mux.Handle("/api/auth/logout", s.requireAuth(http.HandlerFunc(s.handleAuthLogout)))
	s.mux.Handle("/api/auth/me", s.requireAuth(http.HandlerFunc(s.handleAuthMe)))
	s.mux.Handle("/api/user/active-address", s.requireAuth(http.HandlerFunc(s.handleActiveAddress)))

	s.mux.Handle("/api/mailboxes", s.requireAuth(http.HandlerFunc(s.handleMailboxes)))
	s.mux.Handle("/api/messages", s.requireAuth(http.HandlerFunc(s.handleMessagesRoot)))
	s.mux.Handle("/api/messages/", s.requireAuth(http.HandlerFunc(s.handleMessageByID)))

	s.mux.Handle("/api/settings/users", s.requireAuth(http.HandlerFunc(s.handleSettingsUsersRoot)))
	s.mux.Handle("/api/settings/users/", s.requireAuth(http.HandlerFunc(s.handleSettingsUserByID)))
	s.mux.Handle("/api/settings/domains", s.requireAuth(http.HandlerFunc(s.handleSettingsDomainsRoot)))
	s.mux.Handle("/api/settings/domains/", s.requireAuth(http.HandlerFunc(s.handleSettingsDomainByID)))
	s.mux.Handle("/api/settings/addresses", s.requireAuth(http.HandlerFunc(s.handleSettingsAddressesRoot)))
	s.mux.Handle("/api/settings/addresses/", s.requireAuth(http.HandlerFunc(s.handleSettingsAddressByID)))
	s.mux.Handle("/api/settings/mailboxes", s.requireAuth(http.HandlerFunc(s.handleSettingsMailboxesRoot)))
	s.mux.Handle("/api/settings/mailboxes/", s.requireAuth(http.HandlerFunc(s.handleSettingsMailboxByID)))
	s.mux.Handle("/api/settings/access", s.requireAuth(http.HandlerFunc(s.handleSettingsAccessRoot)))
	s.mux.Handle("/api/settings/access/", s.requireAuth(http.HandlerFunc(s.handleSettingsAccessByID)))

	s.mux.Handle("/ws/mail", s.requireAuth(websocket.Handler(s.handleMailWS)))

	s.mountStatic()
}

func (s *Server) mountStatic() {
	distDir := filepath.Join("web", "dist")
	if st, err := os.Stat(distDir); err == nil && st.IsDir() {
		fs := http.FileServer(http.Dir(distDir))
		s.staticFS = fs
		s.mux.Handle("/assets/", fs)
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/" {
				http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
				return
			}

			candidate := filepath.Join(distDir, filepath.Clean(r.URL.Path))
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				http.ServeFile(w, r, candidate)
				return
			}
			http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
		})
		return
	}

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			http.NotFound(w, r)
			return
		}
		jsonError(w, http.StatusNotFound, "web/dist not found; build frontend first")
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func tlsCertPath() string {
	if value := strings.TrimSpace(os.Getenv("TLS_CERT_PATH")); value != "" {
		return value
	}
	return defaultTLSCertPath
}

func tlsKeyPath() string {
	if value := strings.TrimSpace(os.Getenv("TLS_KEY_PATH")); value != "" {
		return value
	}
	return defaultTLSKeyPath
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			jsonError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		sessionID, err := parseUUID(cookie.Value)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid session")
			return
		}

		sessionRow, err := db.Q.GetWebSession(r.Context(), sessionID)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "session expired")
			return
		}

		expires := time.Now().Add(sessionTTL)
		_ = db.Q.ExtendWebSession(r.Context(), db.ExtendWebSessionParams{ID: sessionID, ExpiresAt: pgTimestamp(expires)})
		setSessionCookie(w, sessionID, expires)

		p := Principal{
			SessionID:       sessionRow.ID,
			UserID:          sessionRow.UserID,
			Username:        sessionRow.Username,
			IsAdmin:         sessionRow.IsAdmin,
			ActiveAddressID: sessionRow.ActiveAddressID,
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func principalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := users.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	user, err := db.Q.GetUserByID(r.Context(), userID)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	addresses, err := db.Q.GetUserAddresses(r.Context(), userID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to load addresses")
		return
	}
	var activeAddressID pgtype.UUID
	if len(addresses) > 0 {
		activeAddressID = addresses[0].ID
	}

	expires := time.Now().Add(sessionTTL)
	session, err := db.Q.CreateWebSession(r.Context(), db.CreateWebSessionParams{
		UserID:          user.ID,
		ActiveAddressID: activeAddressID,
		ExpiresAt:       pgTimestamp(expires),
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	setSessionCookie(w, session.ID, expires)
	writeJSON(w, http.StatusOK, map[string]any{
		"userId":          uuidToString(user.ID),
		"username":        user.Username,
		"isAdmin":         user.IsAdmin,
		"activeAddressId": uuidStringOrEmpty(activeAddressID),
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	_ = db.Q.DeleteWebSession(r.Context(), p.SessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	addresses, err := db.Q.GetUserAddresses(r.Context(), p.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to load addresses")
		return
	}

	active := p.ActiveAddressID
	if !active.Valid && len(addresses) > 0 {
		active = addresses[0].ID
		_ = db.Q.SetWebSessionActiveAddress(r.Context(), db.SetWebSessionActiveAddressParams{ID: p.SessionID, ActiveAddressID: active})
	}

	addrPayload := make([]map[string]any, 0, len(addresses))
	for _, a := range addresses {
		addrPayload = append(addrPayload, map[string]any{
			"id":        uuidToString(a.ID),
			"name":      a.Name,
			"domain":    a.DomainName,
			"email":     a.Name + "@" + a.DomainName,
			"createdAt": a.CreatedAt.Time,
			"domainId":  uuidToString(a.Domain),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"userId":            uuidToString(p.UserID),
		"username":          p.Username,
		"isAdmin":           p.IsAdmin,
		"activeAddressId":   uuidStringOrEmpty(active),
		"accessibleAddress": addrPayload,
	})
}

func (s *Server) handleActiveAddress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		AddressID string `json:"addressId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	addressID, err := parseUUID(req.AddressID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid address id")
		return
	}
	canAccess, err := db.Q.UserCanAccessAddress(r.Context(), db.UserCanAccessAddressParams{UserID: p.UserID, AddressID: addressID})
	if err != nil || !canAccess {
		jsonError(w, http.StatusForbidden, "address not accessible")
		return
	}
	if err := db.Q.SetWebSessionActiveAddress(r.Context(), db.SetWebSessionActiveAddressParams{ID: p.SessionID, ActiveAddressID: addressID}); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update active address")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activeAddressId": uuidToString(addressID)})
}

func (s *Server) handleMailboxes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	addressID, err := s.resolveAddressID(r, p)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.ensureAddressAccess(r.Context(), p.UserID, addressID); err != nil {
		jsonError(w, http.StatusForbidden, "address not accessible")
		return
	}

	mailboxes, err := db.Q.ListMailboxesByAddressForUser(r.Context(), db.ListMailboxesByAddressForUserParams{UserID: p.UserID, AddressID: addressID})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list mailboxes")
		return
	}

	items := make([]map[string]any, 0, len(mailboxes))
	for _, m := range mailboxes {
		items = append(items, map[string]any{
			"id":          uuidToString(m.ID),
			"name":        m.Name,
			"type":        nullableMailboxType(m.Type),
			"parentId":    uuidStringOrEmpty(m.ParentID),
			"addressId":   uuidToString(m.AddressID),
			"uidValidity": m.UidValidity,
			"uidNext":     m.UidNext,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleMessagesRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleMessagesList(w, r)
	case http.MethodPost:
		s.handleSendMessage(w, r)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMessageByID(w http.ResponseWriter, r *http.Request) {
	msgIDPart := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	if msgIDPart == "" {
		jsonError(w, http.StatusBadRequest, "missing message id")
		return
	}

	if strings.HasSuffix(msgIDPart, "/flags") {
		idPart := strings.TrimSuffix(msgIDPart, "/flags")
		messageID, err := parseUUID(idPart)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid message id")
			return
		}
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleMessageFlags(w, r, messageID)
		return
	}

	if strings.HasSuffix(msgIDPart, "/move") {
		idPart := strings.TrimSuffix(msgIDPart, "/move")
		messageID, err := parseUUID(idPart)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid message id")
			return
		}
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleMessageMove(w, r, messageID)
		return
	}

	messageID, err := parseUUID(msgIDPart)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleMessageGet(w, r, messageID)
	case http.MethodDelete:
		s.handleMessageDelete(w, r, messageID)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMessagesList(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	addressID, err := s.resolveAddressID(r, p)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.ensureAddressAccess(r.Context(), p.UserID, addressID); err != nil {
		jsonError(w, http.StatusForbidden, "address not accessible")
		return
	}

	mailboxID, err := parseUUID(r.URL.Query().Get("mailboxId"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mailboxId")
		return
	}
	if _, err := db.Q.GetMailboxByIDForAddress(r.Context(), db.GetMailboxByIDForAddressParams{ID: mailboxID, AddressID: addressID}); err != nil {
		jsonError(w, http.StatusNotFound, "mailbox not found")
		return
	}

	cursor := int64(0)
	if v := strings.TrimSpace(r.URL.Query().Get("cursor")); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		cursor = parsed
	}
	limit := int32(50)
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		if parsed > 0 && parsed <= 200 {
			limit = int32(parsed)
		}
	}

	rows, err := db.Q.ListMailboxMessagesPage(r.Context(), db.ListMailboxMessagesPageParams{MailboxID: mailboxID, Column2: cursor, Limit: limit})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list messages")
		return
	}

	items := make([]map[string]any, 0, len(rows))
	nextCursor := int64(0)
	for _, row := range rows {
		subject := getHeader(row.Body, "Subject")
		if subject == "" {
			subject = "(no subject)"
		}
		items = append(items, map[string]any{
			"id":         uuidToString(row.ID),
			"uid":        row.Uid,
			"sender":     row.Sender,
			"recipients": row.Recipients,
			"subject":    subject,
			"flags":      row.Flags,
			"createdAt":  row.CreatedAt.Time,
		})
		nextCursor = row.Uid
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": nextCursor, "hasMore": int32(len(rows)) == limit})
}

func (s *Server) handleMessageGet(w http.ResponseWriter, r *http.Request, messageID pgtype.UUID) {
	p, _ := principalFromContext(r.Context())
	addressID, err := s.resolveAddressID(r, p)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	mailboxID, err := parseUUID(r.URL.Query().Get("mailboxId"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mailboxId")
		return
	}
	if _, err := db.Q.GetMailboxByIDForAddress(r.Context(), db.GetMailboxByIDForAddressParams{ID: mailboxID, AddressID: addressID}); err != nil {
		jsonError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	row, err := db.Q.GetMailboxMessageByEmailID(r.Context(), db.GetMailboxMessageByEmailIDParams{MailboxID: mailboxID, ID: messageID})
	if err != nil {
		jsonError(w, http.StatusNotFound, "message not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         uuidToString(row.ID),
		"uid":        row.Uid,
		"mailboxId":  uuidToString(row.MailboxID),
		"sender":     row.Sender,
		"recipients": row.Recipients,
		"flags":      row.Flags,
		"createdAt":  row.CreatedAt.Time,
		"body":       row.Body,
	})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	var req struct {
		FromAddressID string   `json:"fromAddressId"`
		To            []string `json:"to"`
		Cc            []string `json:"cc"`
		Bcc           []string `json:"bcc"`
		Subject       string   `json:"subject"`
		TextBody      string   `json:"textBody"`
		HTMLBody      string   `json:"htmlBody"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	fromAddressID, err := parseUUID(req.FromAddressID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid fromAddressId")
		return
	}
	if err := s.ensureAddressAccess(r.Context(), p.UserID, fromAddressID); err != nil {
		jsonError(w, http.StatusForbidden, "address not accessible")
		return
	}
	addr, err := db.Q.GetAddressByID(r.Context(), fromAddressID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "sender address not found")
		return
	}
	domain, err := db.Q.GetDomainByID(r.Context(), addr.Domain)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "sender domain not found")
		return
	}
	recipients := mergeRecipients(req.To, req.Cc, req.Bcc)
	if len(recipients) == 0 {
		jsonError(w, http.StatusBadRequest, "at least one recipient is required")
		return
	}

	sender := fmt.Sprintf("<%s@%s>", addr.Name, domain.Name)
	body := buildMultipartMessage(sender, req.To, req.Cc, req.Bcc, req.Subject, req.TextBody, req.HTMLBody)
	if err := peSMTP.SendEmail(r.Context(), p.UserID, sender, wrapRecipients(recipients), body); err != nil {
		jsonError(w, http.StatusBadGateway, "failed to send email")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMessageFlags(w http.ResponseWriter, r *http.Request, messageID pgtype.UUID) {
	var req struct {
		MailboxID   string   `json:"mailboxId"`
		AddFlags    []string `json:"addFlags"`
		RemoveFlags []string `json:"removeFlags"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principalFromContext(r.Context())
	mailboxID, err := parseUUID(req.MailboxID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mailboxId")
		return
	}
	if err := s.ensureMailboxAccess(r.Context(), p.UserID, mailboxID); err != nil {
		jsonError(w, http.StatusForbidden, "mailbox not accessible")
		return
	}
	current, err := db.Q.GetMessageFlagsByEmailInMailbox(r.Context(), db.GetMessageFlagsByEmailInMailboxParams{MailboxID: mailboxID, EmailID: messageID})
	if err != nil {
		jsonError(w, http.StatusNotFound, "message not found")
		return
	}
	final := mutateFlags(current, req.AddFlags, req.RemoveFlags)
	if err := db.Q.UpdateEmailFlags(r.Context(), db.UpdateEmailFlagsParams{EmailID: messageID, MailboxID: mailboxID, Flags: final}); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update flags")
		return
	}
	imap.GlobalMailboxUpdateService.Publish(mailboxID)
	writeJSON(w, http.StatusOK, map[string]any{"flags": final})
}

func (s *Server) handleMessageMove(w http.ResponseWriter, r *http.Request, messageID pgtype.UUID) {
	var req struct {
		FromMailboxID string `json:"fromMailboxId"`
		ToMailboxID   string `json:"toMailboxId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, _ := principalFromContext(r.Context())
	fromMailboxID, err := parseUUID(req.FromMailboxID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid fromMailboxId")
		return
	}
	toMailboxID, err := parseUUID(req.ToMailboxID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid toMailboxId")
		return
	}
	if err := s.ensureMailboxAccess(r.Context(), p.UserID, fromMailboxID); err != nil {
		jsonError(w, http.StatusForbidden, "source mailbox not accessible")
		return
	}
	if err := s.ensureMailboxAccess(r.Context(), p.UserID, toMailboxID); err != nil {
		jsonError(w, http.StatusForbidden, "destination mailbox not accessible")
		return
	}

	row, err := db.Q.GetMailboxMessageByEmailID(r.Context(), db.GetMailboxMessageByEmailIDParams{MailboxID: fromMailboxID, ID: messageID})
	if err != nil {
		jsonError(w, http.StatusNotFound, "message not found")
		return
	}
	uid, err := db.Q.AllocateMailboxUID(r.Context(), toMailboxID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to allocate destination uid")
		return
	}
	if err := db.Q.AssociateEmailToMailbox(r.Context(), db.AssociateEmailToMailboxParams{EmailID: row.ID, MailboxID: toMailboxID, Flags: row.Flags, Uid: int64(uid)}); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to move message")
		return
	}
	if err := db.Q.DeleteEmailFromMailbox(r.Context(), db.DeleteEmailFromMailboxParams{EmailID: row.ID, MailboxID: fromMailboxID}); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to move message")
		return
	}
	_ = db.Q.DeleteOrphanEmails(r.Context())
	imap.GlobalMailboxUpdateService.Publish(fromMailboxID)
	imap.GlobalMailboxUpdateService.Publish(toMailboxID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMessageDelete(w http.ResponseWriter, r *http.Request, messageID pgtype.UUID) {
	p, _ := principalFromContext(r.Context())
	mailboxID, err := parseUUID(r.URL.Query().Get("mailboxId"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mailboxId")
		return
	}
	if err := s.ensureMailboxAccess(r.Context(), p.UserID, mailboxID); err != nil {
		jsonError(w, http.StatusForbidden, "mailbox not accessible")
		return
	}
	if err := db.Q.DeleteEmailFromMailbox(r.Context(), db.DeleteEmailFromMailboxParams{EmailID: messageID, MailboxID: mailboxID}); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete message")
		return
	}
	_ = db.Q.DeleteOrphanEmails(r.Context())
	imap.GlobalMailboxUpdateService.Publish(mailboxID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSettingsUsersRoot(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Q.ListUsers(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to list users")
			return
		}
		items := make([]map[string]any, 0, len(rows))
		for _, u := range rows {
			items = append(items, map[string]any{"id": uuidToString(u.ID), "username": u.Username, "isAdmin": u.IsAdmin, "createdAt": u.CreatedAt.Time})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"isAdmin"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		created, err := db.Q.CreateUserWithPasswordHash(r.Context(), db.CreateUserWithPasswordHashParams{Username: req.Username, PasswordHash: pgtype.Text{String: string(hash), Valid: true}, IsAdmin: req.IsAdmin})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create user")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": uuidToString(created.ID)})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsUserByID(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	id, err := parseUUID(strings.TrimPrefix(r.URL.Path, "/api/settings/users/"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Username string `json:"username"`
			IsAdmin  bool   `json:"isAdmin"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := db.Q.UpdateUserBasics(r.Context(), db.UpdateUserBasicsParams{ID: id, Username: req.Username, IsAdmin: req.IsAdmin}); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to update user")
			return
		}
		if strings.TrimSpace(req.Password) != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to hash password")
				return
			}
			if err := db.Q.UpdateUserPasswordHash(r.Context(), db.UpdateUserPasswordHashParams{ID: id, PasswordHash: pgtype.Text{String: string(hash), Valid: true}}); err != nil {
				jsonError(w, http.StatusBadRequest, "failed to update password")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := db.Q.DeleteUserByID(r.Context(), id); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to delete user")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsDomainsRoot(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := db.Q.ListDomains(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to list domains")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var req struct {
			Name       string `json:"name"`
			SMTPDomain string `json:"smtpDomain"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := db.Q.CreateDomain(r.Context(), db.CreateDomainParams{Name: req.Name, SmtpDomain: req.SMTPDomain})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create domain")
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsDomainByID(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	id, err := parseUUID(strings.TrimPrefix(r.URL.Path, "/api/settings/domains/"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name       string `json:"name"`
			SMTPDomain string `json:"smtpDomain"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		updated, err := db.Q.UpdateDomain(r.Context(), db.UpdateDomainParams{ID: id, Name: req.Name, SmtpDomain: req.SMTPDomain})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to update domain")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.cascadeDeleteDomain(r.Context(), id); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to delete domain")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsAddressesRoot(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		if p.IsAdmin {
			rows, err := db.Q.ListAddressesGlobal(r.Context())
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to list addresses")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": rows})
			return
		}
		rows, err := db.Q.ListAddressesScopedByUser(r.Context(), p.UserID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to list addresses")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		if !p.IsAdmin {
			jsonError(w, http.StatusForbidden, "admin required to create addresses")
			return
		}
		var req struct {
			Name     string `json:"name"`
			DomainID string `json:"domainId"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		domainID, err := parseUUID(req.DomainID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid domain id")
			return
		}
		tx, err := db.Pool.Begin(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create address")
			return
		}
		defer tx.Rollback(r.Context())
		qtx := db.Q.WithTx(tx)

		created, err := qtx.CreateAddress(r.Context(), db.CreateAddressParams{Name: req.Name, Domain: domainID})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create address")
			return
		}
		if err := createDefaultMailboxesForAddress(r.Context(), qtx, created.ID); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create address")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create address")
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsAddressByID(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	id, err := parseUUID(strings.TrimPrefix(r.URL.Path, "/api/settings/addresses/"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid address id")
		return
	}
	if !p.IsAdmin {
		if err := s.ensureAddressAccess(r.Context(), p.UserID, id); err != nil {
			jsonError(w, http.StatusForbidden, "address not accessible")
			return
		}
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name     string `json:"name"`
			DomainID string `json:"domainId"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		domainID, err := parseUUID(req.DomainID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid domain id")
			return
		}
		updated, err := db.Q.UpdateAddress(r.Context(), db.UpdateAddressParams{ID: id, Name: req.Name, Domain: domainID})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to update address")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.cascadeDeleteAddress(r.Context(), id); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to delete address")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsMailboxesRoot(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		if p.IsAdmin {
			rows, err := db.Q.ListMailboxesGlobal(r.Context())
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to list mailboxes")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": rows})
			return
		}
		rows, err := db.Q.ListMailboxesScopedByUser(r.Context(), p.UserID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to list mailboxes")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			Type      string `json:"type"`
			ParentID  string `json:"parentId"`
			AddressID string `json:"addressId"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		addressID, err := parseUUID(req.AddressID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid address id")
			return
		}
		if !p.IsAdmin {
			if err := s.ensureAddressAccess(r.Context(), p.UserID, addressID); err != nil {
				jsonError(w, http.StatusForbidden, "address not accessible")
				return
			}
		}
		mailboxType, err := parseMailboxType(req.Type)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid mailbox type")
			return
		}
		parentID := pgtype.UUID{}
		if strings.TrimSpace(req.ParentID) != "" {
			parentID, err = parseUUID(req.ParentID)
			if err != nil {
				jsonError(w, http.StatusBadRequest, "invalid parent id")
				return
			}
		}
		created, err := db.Q.CreateMailboxFull(r.Context(), db.CreateMailboxFullParams{Name: req.Name, Type: mailboxType, ParentID: parentID, AddressID: addressID})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create mailbox")
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsMailboxByID(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	id, err := parseUUID(strings.TrimPrefix(r.URL.Path, "/api/settings/mailboxes/"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mailbox id")
		return
	}
	if !p.IsAdmin {
		if err := s.ensureMailboxAccess(r.Context(), p.UserID, id); err != nil {
			jsonError(w, http.StatusForbidden, "mailbox not accessible")
			return
		}
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			ParentID string `json:"parentId"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		mailboxType, err := parseMailboxType(req.Type)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid mailbox type")
			return
		}
		parentID := pgtype.UUID{}
		if strings.TrimSpace(req.ParentID) != "" {
			parentID, err = parseUUID(req.ParentID)
			if err != nil {
				jsonError(w, http.StatusBadRequest, "invalid parent id")
				return
			}
		}
		updated, err := db.Q.UpdateMailbox(r.Context(), db.UpdateMailboxParams{ID: id, Name: req.Name, Type: mailboxType, ParentID: parentID})
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to update mailbox")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.cascadeDeleteMailbox(r.Context(), id); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to delete mailbox")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsAccessRoot(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		if p.IsAdmin {
			rows, err := db.Q.ListUserAddressAccessGlobal(r.Context())
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to list access")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": rows})
			return
		}
		rows, err := db.Q.ListUserAddressAccessScopedByUser(r.Context(), p.UserID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to list access")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		if !p.IsAdmin {
			jsonError(w, http.StatusForbidden, "admin required")
			return
		}
		var req struct {
			UserID    string `json:"userId"`
			AddressID string `json:"addressId"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		userID, err := parseUUID(req.UserID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid user id")
			return
		}
		addressID, err := parseUUID(req.AddressID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid address id")
			return
		}
		if err := db.Q.CreateUserAddressAccess(r.Context(), db.CreateUserAddressAccessParams{UserID: userID, AddressID: addressID}); err != nil {
			jsonError(w, http.StatusBadRequest, "failed to create access")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettingsAccessByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, _ := principalFromContext(r.Context())
	if !p.IsAdmin {
		jsonError(w, http.StatusForbidden, "admin required")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/settings/access/"), "/")
	if len(parts) != 2 {
		jsonError(w, http.StatusBadRequest, "expected /api/settings/access/{userId}/{addressId}")
		return
	}
	userID, err := parseUUID(parts[0])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	addressID, err := parseUUID(parts[1])
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid address id")
		return
	}
	if err := db.Q.DeleteUserAddressAccess(r.Context(), db.DeleteUserAddressAccessParams{UserID: userID, AddressID: addressID}); err != nil {
		jsonError(w, http.StatusBadRequest, "failed to delete access")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMailWS(ws *websocket.Conn) {
	defer ws.Close()
	ctx := ws.Request().Context()
	p, ok := principalFromContext(ctx)
	if !ok {
		_ = websocket.JSON.Send(ws, map[string]any{"type": "error", "error": "unauthorized"})
		return
	}

	mailboxID, err := parseUUID(ws.Request().URL.Query().Get("mailboxId"))
	if err != nil {
		_ = websocket.JSON.Send(ws, map[string]any{"type": "error", "error": "invalid mailboxId"})
		return
	}
	if err := s.ensureMailboxAccess(ctx, p.UserID, mailboxID); err != nil {
		_ = websocket.JSON.Send(ws, map[string]any{"type": "error", "error": "forbidden"})
		return
	}

	updates := make(chan struct{}, 1)
	imap.GlobalMailboxUpdateService.Subscribe(mailboxID, updates)
	defer imap.GlobalMailboxUpdateService.Unsubscribe(mailboxID, updates)

	_ = websocket.JSON.Send(ws, map[string]any{"type": "connected", "mailboxId": uuidToString(mailboxID)})

	for {
		select {
		case <-updates:
			if err := websocket.JSON.Send(ws, map[string]any{
				"type":      "mailbox.exists",
				"mailboxId": uuidToString(mailboxID),
				"ts":        time.Now().UTC(),
			}); err != nil {
				return
			}
		case <-time.After(30 * time.Second):
			if err := websocket.JSON.Send(ws, map[string]any{"type": "ping", "ts": time.Now().UTC()}); err != nil {
				return
			}
		}
	}
}

func (s *Server) resolveAddressID(r *http.Request, p Principal) (pgtype.UUID, error) {
	if v := strings.TrimSpace(r.URL.Query().Get("addressId")); v != "" {
		return parseUUID(v)
	}
	if p.ActiveAddressID.Valid {
		return p.ActiveAddressID, nil
	}
	addresses, err := db.Q.GetUserAddresses(r.Context(), p.UserID)
	if err != nil || len(addresses) == 0 {
		return pgtype.UUID{}, fmt.Errorf("no active address")
	}
	return addresses[0].ID, nil
}

func (s *Server) ensureAddressAccess(ctx context.Context, userID, addressID pgtype.UUID) error {
	allowed, err := db.Q.UserCanAccessAddress(ctx, db.UserCanAccessAddressParams{UserID: userID, AddressID: addressID})
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("forbidden")
	}
	return nil
}

func (s *Server) ensureMailboxAccess(ctx context.Context, userID, mailboxID pgtype.UUID) error {
	addresses, err := db.Q.GetUserAddresses(ctx, userID)
	if err != nil {
		return err
	}
	for _, addr := range addresses {
		if _, err := db.Q.GetMailboxByIDForAddress(ctx, db.GetMailboxByIDForAddressParams{ID: mailboxID, AddressID: addr.ID}); err == nil {
			return nil
		}
	}
	return fmt.Errorf("forbidden")
}

func (s *Server) cascadeDeleteMailbox(ctx context.Context, mailboxID pgtype.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := db.Q.WithTx(tx)
	if err := qtx.DeleteEmailMailboxByMailboxID(ctx, mailboxID); err != nil {
		return err
	}
	if err := qtx.DeleteMailboxByID(ctx, mailboxID); err != nil {
		return err
	}
	if err := qtx.DeleteOrphanEmails(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) cascadeDeleteAddress(ctx context.Context, addressID pgtype.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := db.Q.WithTx(tx)
	mailboxes, err := qtx.ListMailboxesGlobal(ctx)
	if err != nil {
		return err
	}
	for _, m := range mailboxes {
		if m.AddressID != addressID {
			continue
		}
		if err := qtx.DeleteEmailMailboxByMailboxID(ctx, m.ID); err != nil {
			return err
		}
	}
	if err := qtx.DeleteMailboxesByAddressID(ctx, addressID); err != nil {
		return err
	}
	if err := qtx.DeleteUserAddressByAddressID(ctx, addressID); err != nil {
		return err
	}
	if err := qtx.DeleteAddressByID(ctx, addressID); err != nil {
		return err
	}
	if err := qtx.DeleteOrphanEmails(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) cascadeDeleteDomain(ctx context.Context, domainID pgtype.UUID) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := db.Q.WithTx(tx)
	addresses, err := qtx.ListAddressesGlobal(ctx)
	if err != nil {
		return err
	}
	mailboxes, err := qtx.ListMailboxesGlobal(ctx)
	if err != nil {
		return err
	}
	for _, a := range addresses {
		if a.Domain != domainID {
			continue
		}
		for _, m := range mailboxes {
			if m.AddressID == a.ID {
				if err := qtx.DeleteEmailMailboxByMailboxID(ctx, m.ID); err != nil {
					return err
				}
			}
		}
		if err := qtx.DeleteMailboxesByAddressID(ctx, a.ID); err != nil {
			return err
		}
		if err := qtx.DeleteUserAddressByAddressID(ctx, a.ID); err != nil {
			return err
		}
	}
	if err := qtx.DeleteAddressesByDomainID(ctx, domainID); err != nil {
		return err
	}
	if err := qtx.DeleteDomainByID(ctx, domainID); err != nil {
		return err
	}
	if err := qtx.DeleteOrphanEmails(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func setSessionCookie(w http.ResponseWriter, sessionID pgtype.UUID, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    uuidToString(sessionID),
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

func cookieSecure() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("COOKIE_SECURE")))
	switch value {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid json payload")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode failed: %v", err)
	}
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func parseUUID(value string) (pgtype.UUID, error) {
	var id pgtype.UUID
	if err := id.Scan(strings.TrimSpace(value)); err != nil {
		return pgtype.UUID{}, err
	}
	return id, nil
}

func uuidToString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	b := id.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func uuidStringOrEmpty(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuidToString(id)
}

func pgTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func nullableMailboxType(m db.NullMailboxType) string {
	if !m.Valid {
		return ""
	}
	return string(m.MailboxType)
}

func parseMailboxType(value string) (db.NullMailboxType, error) {
	trimmed := strings.TrimSpace(strings.ToUpper(value))
	if trimmed == "" {
		return db.NullMailboxType{}, nil
	}
	allowed := map[string]db.MailboxType{
		"INBOX":   db.MailboxTypeINBOX,
		"DRAFTS":  db.MailboxTypeDRAFTS,
		"SENT":    db.MailboxTypeSENT,
		"TRASH":   db.MailboxTypeTRASH,
		"SPAM":    db.MailboxTypeSPAM,
		"ARCHIVE": db.MailboxTypeARCHIVE,
	}
	v, ok := allowed[trimmed]
	if !ok {
		return db.NullMailboxType{}, fmt.Errorf("invalid mailbox type")
	}
	return db.NullMailboxType{MailboxType: v, Valid: true}, nil
}

func createDefaultMailboxesForAddress(ctx context.Context, q *db.Queries, addressID pgtype.UUID) error {
	defaultMailboxes := []db.MailboxType{
		db.MailboxTypeINBOX,
		db.MailboxTypeDRAFTS,
		db.MailboxTypeSENT,
		db.MailboxTypeTRASH,
		db.MailboxTypeSPAM,
		db.MailboxTypeARCHIVE,
	}
	for _, mailboxType := range defaultMailboxes {
		if _, err := q.CreateMailboxFull(ctx, db.CreateMailboxFullParams{
			Name:      string(mailboxType),
			Type:      db.NullMailboxType{MailboxType: mailboxType, Valid: true},
			ParentID:  pgtype.UUID{},
			AddressID: addressID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func mergeRecipients(parts ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, group := range parts {
		for _, raw := range group {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			key := strings.ToLower(v)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func wrapRecipients(recipients []string) []string {
	out := make([]string, 0, len(recipients))
	for _, rcpt := range recipients {
		v := strings.TrimSpace(rcpt)
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
			out = append(out, v)
		} else {
			out = append(out, "<"+v+">")
		}
	}
	return out
}

func buildMultipartMessage(sender string, to, cc, bcc []string, subject, textBody, htmlBody string) string {
	if textBody == "" {
		textBody = htmlToTextFallback(htmlBody)
	}
	if htmlBody == "" {
		htmlBody = strings.ReplaceAll(textBody, "\n", "<br>")
	}
	boundary := fmt.Sprintf("mixed-%d", time.Now().UnixNano())
	altBoundary := fmt.Sprintf("alt-%d", time.Now().UnixNano())

	headers := []string{
		fmt.Sprintf("From: %s", strings.Trim(sender, "<>")),
		fmt.Sprintf("To: %s", strings.Join(to, ", ")),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123Z)),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q", altBoundary),
	}
	if len(cc) > 0 {
		headers = append(headers, fmt.Sprintf("Cc: %s", strings.Join(cc, ", ")))
	}
	if len(bcc) > 0 {
		headers = append(headers, fmt.Sprintf("Bcc: %s", strings.Join(bcc, ", ")))
	}

	var sb strings.Builder
	sb.WriteString(strings.Join(headers, "\r\n"))
	sb.WriteString("\r\n\r\n")
	sb.WriteString("--" + altBoundary + "\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	sb.WriteString(textBody + "\r\n")
	sb.WriteString("--" + altBoundary + "\r\n")
	sb.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	sb.WriteString(htmlBody + "\r\n")
	sb.WriteString("--" + altBoundary + "--\r\n")

	_ = boundary
	return sb.String()
}

func htmlToTextFallback(html string) string {
	if html == "" {
		return ""
	}
	// Minimal fallback: strip tags naively.
	replacer := strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p>", "\n\n")
	text := replacer.Replace(html)
	for {
		start := strings.Index(text, "<")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], ">")
		if end == -1 {
			break
		}
		text = text[:start] + text[start+end+1:]
	}
	return strings.TrimSpace(text)
}

func getHeader(raw, name string) string {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(name)+":") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, name+":"))
		}
	}
	return ""
}

func mutateFlags(current, add, remove []string) []string {
	set := map[string]struct{}{}
	for _, flag := range current {
		set[strings.TrimSpace(flag)] = struct{}{}
	}
	for _, flag := range add {
		flag = strings.TrimSpace(flag)
		if flag != "" {
			set[flag] = struct{}{}
		}
	}
	for _, flag := range remove {
		delete(set, strings.TrimSpace(flag))
	}
	out := make([]string, 0, len(set))
	for flag := range set {
		if flag != "" {
			out = append(out, flag)
		}
	}
	return out
}

type WSHub struct{}

func NewWSHub() *WSHub { return &WSHub{} }

func EnsureBootstrapAdmin(ctx context.Context) error {
	username := strings.TrimSpace(os.Getenv("ADMIN_BOOTSTRAP_USERNAME"))
	if username == "" {
		return nil
	}
	user, err := db.Q.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if user.IsAdmin {
		return nil
	}
	_, err = db.Q.UpdateUserBasics(ctx, db.UpdateUserBasicsParams{ID: user.ID, Username: user.Username, IsAdmin: true})
	return err
}
