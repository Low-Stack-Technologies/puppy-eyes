# IMAP Implementation Issues & TODOs

## Protocol Compliance & Capability Advertisement
- [ ] **Fix CAPABILITY after STARTTLS**: 
  - Currently, `AUTH=PLAIN` is not advertised in the capability list. 
  - `curl` fails with "SASL: no auth mechanism was offered or recognized" because the server claims to support `SASL-IR` but lists no authentication mechanisms (like `AUTH=PLAIN`) in the capability response.
  - *Action*: Add `AUTH=PLAIN` to the capabilities list, especially after TLS is established.

## Command Support
- [x] **Implement `UID` Command**:
  - `curl` (and many clients) use `UID FETCH` instead of just `FETCH`.
  - The current parser treats `UID` as a command, but there is no `case "UID":` handler.
  - *Action*: Implement a handler for `UID` that parses the subsequent command (e.g., `FETCH`, `COPY`, `STORE`) and executes it using UIDs instead of sequence numbers.

- [ ] **Implement `STORE` Command**:
  - Currently returns "To be implemented". Required for flag updates (read/seen status, deletion).

- [ ] **Implement `EXPUNGE` Command**:
  - Currently returns "To be implemented". Required for permanently removing deleted messages.

## Response Formatting
- [x] **Fix `FETCH ENVELOPE` Structure**:
  - `curl` fails to parse the FETCH response: `Failed to parse FETCH response`.
  - The current implementation sends email addresses as a single string list `("<user@intradisp.se>")`.
  - **Standard Requirement**: IMAP address structures must be a parenthesized list of four fields: `(display-name, source-route, mailbox-name, hostname)`. 
  - *Example*: `("User Name" NIL "user" "intradisp.se")`.
  - *Action*: Update the ENVELOPE generation logic to properly split email addresses into these components.

- [x] **Fix `FETCH` Body Structure**:
  - The server sends `BODY[]` content. Ensure strict adherence to RFC 3501 for the body structure format to prevent parsing errors in stricter clients.
