# SMTP Server Implementation Reference

## 1. Client Submission (MSA - Mail Submission Agent)
**Context:** An email client (e.g., Thunderbird, Outlook) connects to your server to send an email.
**Standard Port:** 587 (preferred) or 465 (Implicit TLS).
**Key Requirement:** Authentication is mandatory to prevent open relay abuse.

### Protocol Flow
1.  **Connection Establishment**
    * Server: `220 smtp.yourdomain.com ESMTP Service Ready`
2.  **Handshake**
    * Client: `EHLO client-machine-name`
    * Server: `250-smtp.yourdomain.com`
    * Server: `250-STARTTLS` (Advertise TLS support)
    * Server: `250-AUTH LOGIN PLAIN` (Advertise Auth mechanisms)
    * Server: `250 8BITMIME`
3.  **Security Upgrade (If not on port 465)**
    * Client: `STARTTLS`
    * Server: `220 2.0.0 Ready to start TLS`
    * *(TLS Handshake occurs here. All subsequent traffic is encrypted.)*
    * Client: `EHLO client-machine-name` (Resend EHLO inside encrypted tunnel)
    * Server: `250...` (Responses repeated)
4.  **Authentication**
    * Client: `AUTH PLAIN <base64_string>`
    * Server: `235 2.7.0 Authentication successful`
    * *Failure Case:* `535 5.7.8 Authentication failed`
5.  **Envelope Construction**
    * Client: `MAIL FROM:<user@yourdomain.com>`
    * Server: `250 2.1.0 Sender OK`
    * Client: `RCPT TO:<recipient@example.com>`
    * Server: `250 2.1.5 Recipient OK`
6.  **Data Transmission**
    * Client: `DATA`
    * Server: `354 Start mail input; end with <CRLF>.<CRLF>`
    * Client: *(Sends headers and body)*
    * Client: `.`
    * Server: `250 2.0.0 OK: queued as <QueueID>`
7.  **Termination**
    * Client: `QUIT`
    * Server: `221 2.0.0 Bye`

---

## 2. Sending to Other Servers (MTA - Outbound)
**Context:** Your server relaying an email to an external destination (e.g., Gmail).
**Standard Port:** 25.
**Key Requirement:** Must handle MX record lookups and respect the recipient's policies (SPF/DKIM).

### Protocol Flow
1.  **Preparation**
    * *Internal:* Look up `MX` record for `destination.com` (e.g., `alt1.gmail-smtp-in.l.google.com`).
    * *Internal:* Connect to the resolved IP on port 25.
2.  **Handshake**
    * External Server: `220 mx.google.com ESMTP...`
    * Your Server: `EHLO smtp.yourdomain.com`
    * External Server: `250-mx.google.com...` (Lists capabilities)
3.  **Opportunistic TLS (Highly Recommended)**
    * *If External Server advertised STARTTLS:*
    * Your Server: `STARTTLS`
    * External Server: `220 2.0.0 Ready to start TLS`
    * *(Perform TLS Handshake)*
    * Your Server: `EHLO smtp.yourdomain.com`
4.  **Transaction**
    * Your Server: `MAIL FROM:<user@yourdomain.com>`
    * External Server: `250 2.1.0 OK`
    * Your Server: `RCPT TO:<dest@destination.com>`
    * External Server: `250 2.1.5 OK`
    * *Failure Case (User doesn't exist):* `550 5.1.1 The email account that you tried to reach does not exist.`
5.  **Data Transmission**
    * Your Server: `DATA`
    * External Server: `354 Go ahead`
    * Your Server: *(Sends email content)*
    * Your Server: `.`
    * External Server: `250 2.0.0 OK 1234567890 - gsmtp`
6.  **Termination**
    * Your Server: `QUIT`

---
# 3. Receiving from Other Servers (MTA - Inbound) with Authentication
**Context:** An external server (e.g., Google, Outlook) connects to you to deliver mail.
**Goal:** Receive valid mail, reject spam/spoofing, and prevent open relay.

### Protocol Flow

1.  **Connection & Handshake**
    * **Server:** `220 smtp.yourdomain.com ESMTP Postfix`
    * **External:** `EHLO mail.google.com`
    * **Server:** `250-smtp.yourdomain.com...` (Advertise STARTTLS, 8BITMIME, SIZE)

2.  **Envelope - The SPF Checkpoint**
    * **External:** `MAIL FROM:<sender@gmail.com>`
    * **Server Action (SPF Check):**
        1.  Extract domain `gmail.com`.
        2.  Fetch DNS TXT record for `gmail.com`.
        3.  Verify if connecting IP is authorized.
        4.  *Save Result:* `SPF_PASS`, `SPF_FAIL`, or `SPF_SOFTFAIL`.
    * **Server Response:** `250 2.1.0 OK` (Even if SPF fails, usually wait for DMARC later unless it is a hard fail `-all`).

3.  **Recipient & Relay Check**
    * **External:** `RCPT TO:<user@yourdomain.com>`
    * **Server Action:** Verify `yourdomain.com` is hosted locally.
    * **Server Response:** `250 2.1.5 OK`

4.  **Data Transmission - The DKIM Checkpoint**
    * **External:** `DATA`
    * **Server:** `354 End data with <CRLF>.<CRLF>`
    * **External:** *(Sends Headers + Body)*
    * **External:** `.` (End of Data)
    * **Server Action (DKIM Check):**
        1.  Parse headers for `DKIM-Signature`.
        2.  Fetch public key from DNS selector.
        3.  Verify cryptographic signature of body/headers.
        4.  *Save Result:* `DKIM_PASS` or `DKIM_FAIL`.

5.  **Policy Enforcement - The DMARC Evaluation**
    * **Trigger:** Happens immediately after Data is received, but *before* sending the final OK.
    * **Server Action (DMARC Logic):**
        1.  **Alignment:** specific check comparing "Header From" domain vs. "Envelope From" (SPF) and "d=" tag (DKIM).
        2.  **Fetch Policy:** DNS TXT lookup `_dmarc.gmail.com` (e.g., `v=DMARC1; p=reject`).
        3.  **Evaluate:**
            * IF (SPF=Pass OR DKIM=Pass) AND Alignment=OK -> **DMARC PASS**.
            * ELSE -> **DMARC FAIL**.
        4.  **Apply Policy (If Fail):**
            * `p=none`: Log it, accept mail.
            * `p=quarantine`: Accept mail, but route to "Spam" folder.
            * `p=reject`: **Reject** the transaction.

6.  **Final Response (The Verdict)**
    * **If DMARC Pass (or p=none/quarantine):**
        * **Server:** `250 2.0.0 OK: queued as <QueueID>`
    * **If DMARC Fail (and p=reject):**
        * **Server:** `550 5.7.1 Unauthenticated email from gmail.com is not accepted due to domain's DMARC policy.`

7.  **Termination**
    * **External:** `QUIT`
