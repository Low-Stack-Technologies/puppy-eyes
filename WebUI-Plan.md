## Web UI for Puppy Eyes: React Webmail + Settings Console

### Summary

Build a single-binary Go + React (Vite + TypeScript) web application that provides:

1. Login with username/password via secure cookie session.
2. Full webmail client behavior (mailbox list, message list/read, compose/send, flags, move/delete).
3. Settings console with full CRUD for users, domains, addresses, mailboxes, and user-address access.
4. Multi-address mailbox viewing via an explicit active-address selector.
5. Mixed protocol backend strategy: IMAP for read flows, SMTP for send flows, DB-backed API for settings.
6. Long-lived IMAP sessions with IDLE and WebSocket push for realtime mailbox updates.

### Scope and Product Rules

1. Frontend stack: React + Vite + TypeScript, shadcn/ui component library.
2. Runtime shape: one Go binary serves API + websocket + static SPA assets.
3. Compose format: multipart text+HTML.
4. Mail list UX: infinite scroll.
5. Account lifecycle: no public signup; users managed in Settings.
6. Address UX: global active-address selector; all mailbox views filter to selected address.
7. Authorization model (hybrid): Users and Domains are admin-only; Addresses, Mailboxes, User Address
   Access are scoped to addresses the user can access.
8. Delete policy: cascade deletes (implemented in service layer transactions even where DB FKs are not
   cascading).

### Public APIs / Interfaces / Types to Add

1. POST /api/auth/login with { username, password } and cookie session issuance.
2. POST /api/auth/logout.
3. GET /api/auth/me returning { userId, username, isAdmin, accessibleAddresses, activeAddressId }.
4. PUT /api/user/active-address with { addressId }.
5. GET /api/mailboxes?addressId=....
6. GET /api/messages?addressId=...&mailboxId=...&cursor=...&limit=... for infinite scroll.
7. GET /api/messages/:id?addressId=...&mailboxId=....
8. POST /api/messages/send with { fromAddressId, to[], cc[], bcc[], subject, textBody, htmlBody }.
9. POST /api/messages/:id/flags with { mailboxId, addFlags[], removeFlags[] }.
10. POST /api/messages/:id/move with { fromMailboxId, toMailboxId }.
11. DELETE /api/messages/:id with { mailboxId }.
12. GET /api/settings/users / POST / PUT /:id / DELETE /:id (admin-only).
13. GET /api/settings/domains / POST / PUT /:id / DELETE /:id (admin-only).
14. GET /api/settings/addresses / POST / PUT /:id / DELETE /:id (scoped).
15. GET /api/settings/mailboxes / POST / PUT /:id / DELETE /:id (scoped).
16. GET /api/settings/access / POST / DELETE for user-address links (scoped).
17. GET /ws/mail?addressId=...&mailboxId=... websocket stream with events like mailbox.exists,
   message.flags.changed, message.added, message.removed.
18. New backend types:
   WebSession { id, userId, expiresAt }, AuthUser { id, username, isAdmin }, ActiveAddressContext
   { userId, addressId }, WsMailEvent { type, addressId, mailboxId, payload }.

### Backend Implementation Plan

1. Add HTTP server package internal/http and start it from cmd/server/main.go alongside SMTP/IMAP/worker
   goroutines.
2. Add migrations:
   users.is_admin BOOLEAN NOT NULL DEFAULT FALSE,
   users.password_hash TEXT,
   web_sessions table for server-side sessions.
3. Password migration strategy:
   on first successful plaintext login, hash with bcrypt and store in password_hash; then authenticate
   using hash; retain backward-compatible fallback until all users are migrated; add a follow-up command/
   check to enforce hash-only.
4. Add ADMIN_BOOTSTRAP_USERNAME env behavior at startup:
   if set, ensure matching user exists and is_admin=true.
5. Implement cookie auth middleware:
   HTTP-only, Secure (in TLS), SameSite=Lax, server-side session lookup, rolling expiry.
6. Implement authorization middleware:
   RequireAuth, RequireAdmin, and scoped-address checks for scoped settings + mail actions.
7. IMAP proxy subsystem:
   maintain long-lived per-user IMAP connections keyed by user session; support mailbox select/fetch/
   store; run IDLE loop and publish updates to websocket hub.
8. SMTP send subsystem:
   submit outbound mail via SMTP AUTH to local submission endpoint using logged-in user credentials and
   selected fromAddress; include generated MIME multipart text+HTML; rely on current server behavior to
   place sent copies.
9. Settings service layer:
   transactional cascade delete handlers for each entity so dependent joins/mailboxes/emails are removed
   deterministically and safely.
10. Keep protocol servers as-is for external clients; web API is additive and does not replace IMAP/SMTP.

### Frontend Implementation Plan (React)

1. Create web/ app with Vite + TS + React Router + shadcn/ui.
2. App shell with left sidebar:
   address selector at top, navigation to Mail and Settings.
3. Mail pages:
   mailbox list, message list (infinite scroll), message detail, compose modal/page, flag/move/delete
   actions.
4. WebSocket client:
   connect on mailbox view and update list state live from events.
5. Settings pages:
   Users, Domains, Addresses, Mailboxes, User Address Access; hide admin-only tabs for non-admin users.
6. Auth flow:
   login page, protected routes, me bootstrap call, logout action.
7. Styling:
   design tokens + shadcn primitives; responsive desktop/mobile layouts.

### Test Cases and Scenarios

1. Auth:
   login success/failure, cookie expiry, logout, hashed-password login, plaintext-to-hash migration path.
2. Authorization:
   non-admin blocked from Users/Domains; scoped users blocked from foreign addresses/mailboxes/access
   links.
3. Address selector:
   user with multiple addresses switches active address and sees only relevant mailboxes/messages.
4. Webmail read:
   mailbox list retrieval, infinite cursor paging, message open, flags update, move/delete behavior.
5. Compose:
   multipart generation correctness, SMTP submit success/failure handling, sent mailbox copy visibility.
6. Realtime:
   new inbound mail triggers IMAP IDLE event and websocket update in active mailbox.
7. Settings CRUD:
   full create/update/delete lifecycle for all entities, including cascade delete integrity.
8. Protocol compatibility regression:
   existing IMAP/SMTP tests still pass unchanged after web layer addition.
9. End-to-end smoke:
   start single binary, login via browser, switch address, read/send mail, manage settings.

### Assumptions and Defaults Chosen

1. React choice is finalized as Vite + TypeScript.
2. WebSocket push is required in MVP (not polling fallback-first).
3. Cascade delete means application-managed transactional cascades where DB schema lacks FK cascade.
4. IMAP read path is mandatory for webmail read operations; settings stays DB/API-native.
5. Hybrid authorization is final:
   Users + Domains admin-only;
   Addresses + Mailboxes + UserAddressAccess scoped by accessible addresses.
6. Active address is persisted per web session and used as default filter across mail routes.
