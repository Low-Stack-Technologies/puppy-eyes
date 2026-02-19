# IMAP Implementation Issues & TODOs

## Protocol Compliance & Capability Advertisement
- [x] **Fix CAPABILITY after STARTTLS**: 
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

## DNS & Email Security (SPF/DMARC)

### SPF (RFC 7208)
- [x] **Missing Mechanisms**: Implement the `a`, `mx`, `ptr`, and `exists` mechanisms which are currently skipped. These are essential because many domains authorize their own IP addresses via their existing DNS records rather than explicit IP lists.
- [x] **Macro Support**: Add support for SPF macros like `%{i}`, `%{d}`, and `%{s}` which allow for dynamic record lookups based on sender attributes. Without this, records containing macros will fail to parse correctly or yield incorrect results.
- [ ] **RFC-Compliant DNS Limits**: Enforce the strict RFC 7208 limit of 10 DNS-interactive mechanisms per SPF check to prevent Denial of Service attacks. This requires a counter that persists across nested `include` and `redirect` mechanisms.
- [x] **Result Granularity**: Expand the return types to distinguish between `Pass`, `Fail`, `SoftFail`, `Neutral`, `None`, `TempError`, and `PermError`. This granularity is necessary for sophisticated spam filtering and proper DMARC evaluation.

### DMARC (RFC 7489)
- [x] **Alignment Checks**: Implement logic to verify that the domain in the `From:` header is in "alignment" with the domain validated by SPF or DKIM. This is the core of DMARC and prevents "friendly-from" spoofing where the envelope sender is valid but the visible sender is not.
- [x] **Organizational Domain Fallback**: If a DMARC record is not found for a subdomain, the implementation must look up the record for the organizational (root) domain. This ensures that policies applied to a top-level domain correctly protect its subdomains.
- [x] **Tag Support**: Support additional tags such as `pct` for graduated rollouts, `sp` for subdomain-specific policies, and `adkim`/`aspf` for strict vs. relaxed alignment modes. These tags allow domain owners to fine-tune how their policy is applied.
- [x] **Reporting**: Add the ability to generate and send Aggregate (RUA) and Forensic/Failure (RUF) reports as specified in the DMARC record. These reports provide domain owners with visibility into who is sending mail on their behalf.

### DKIM
- [x] **DKIM Signature Verification**: Implement the cryptographic verification of `DKIM-Signature` headers using public keys retrieved from DNS. This provides a second, robust method of sender authentication that is more resilient to mail forwarding than SPF.
- [x] **DKIM Signing**: Implement the ability to sign outgoing emails with a DKIM signature using a private key. This involves generating the `DKIM-Signature` header by hashing the message body and selected headers, ensuring that our sent mail is verifiable by receiving servers and improving deliverability.
