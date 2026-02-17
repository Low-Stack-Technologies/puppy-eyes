### 1. Connection & Handshake
1.  **Connection Establishment**
    * Server: `* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] IMAP4rev1 Service Ready`
    * *(Note: LOGINDISABLED prevents plaintext login before TLS)*

2.  **Security Upgrade (If on Port 143)**
    * Client: `A001 STARTTLS`
    * Server: `A001 OK Begin TLS negotiation now`
    * *(TLS Handshake occurs. Session restarts inside tunnel.)*

3.  **Authentication**
    * Client: `A002 LOGIN user@yourdomain.com password123`
    * Server: `A002 OK User logged in`
    * *Failure Case:* `A002 NO [AUTHENTICATIONFAILED] Invalid credentials`

    * *(Alternative: XOAUTH2 or AUTHENTICATE PLAIN)*
    * Client: `A003 AUTHENTICATE PLAIN`
    * Server: `+` (Continuation request)
    * Client: `<base64_string>`
    * Server: `A003 OK Success`

### 2. Folder Navigation
1.  **List Folders (Discovery)**
    * Client: `A004 LIST "" "*"`
    * Server: `* LIST (\HasNoChildren) "/" "INBOX"`
    * Server: `* LIST (\HasNoChildren) "/" "Sent"`
    * Server: `* LIST (\HasChildren) "/" "Work"`
    * Server: `A004 OK List completed`

2.  **Select Mailbox (Entering 'Selected' State)**
    * Client: `A005 SELECT INBOX`
    * *Server sends the state of the mailbox:*
    * Server: `* 172 EXISTS` (Total messages)
    * Server: `* 1 RECENT` (New since last connect)
    * Server: `* OK [UNSEEN 12] Message 12 is first unseen`
    * Server: `* OK [UIDVALIDITY 3857529045] UIDs valid`
    * Server: `* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)`
    * Server: `A005 OK [READ-WRITE] Select completed`

### 3. Fetching Data
1.  **Fetch List of Headers (For the UI List)**
    * Client: `A006 FETCH 1:* (UID ENVELOPE FLAGS)`
        * *1:* means "from message 1 to the end"*
    * Server: `* 1 FETCH (UID 101 FLAGS (\Seen) ENVELOPE ("Date" "Subject" ...))`
    * Server: `* 2 FETCH (UID 102 FLAGS () ENVELOPE ("Date" ...))`
    * Server: `A006 OK Fetch completed`

2.  **Fetch Message Body (Reading an Email)**
    * Client: `A007 FETCH 2 (BODY[])`
    * Server: `* 2 FETCH (BODY[] {4096}`
    * Server: `(Raw bytes of the email headers + body go here)`
    * Server: `)`
    * Server: `A007 OK Fetch completed`

    * *Optimization (MIME Parsing):*
    * Client: `A008 FETCH 2 (BODYSTRUCTURE)`
    * Server: `* 2 FETCH (BODYSTRUCTURE ("TEXT" "PLAIN" ...))` (Client downloads only attachment or text part)

### 4. Operations
1.  **Mark as Read (Flags)**
    * Client: `A009 STORE 2 +FLAGS (\Seen)`
    * Server: `* 2 FETCH (FLAGS (\Seen))`
    * Server: `A009 OK Store completed`

2.  **Delete / Move**
    * *IMAP deletion is a two-step process: Mark \Deleted, then Expunge.*
    * Client: `A010 STORE 2 +FLAGS (\Deleted)`
    * Server: `* 2 FETCH (FLAGS (\Deleted \Seen))`
    * Server: `A010 OK Store completed`
    * Client: `A011 EXPUNGE`
    * Server: `* 2 EXPUNGE` (Server confirms msg 2 is gone)
    * Server: `A011 OK Expunge completed`

3.  **Real-time Push (IDLE Extension)**
    * Client: `A012 IDLE`
    * Server: `+ idling`
    * *(Connection hangs open. If new mail arrives:)*
    * Server: `* 173 EXISTS`
    * *(Client wants to stop idling to send a command:)*
    * Client: `DONE`
    * Server: `A012 OK Idle terminated`