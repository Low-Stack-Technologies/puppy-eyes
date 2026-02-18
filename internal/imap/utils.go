package imap

import (
	"fmt"
	"strings"
)

func parseIMAPLine(line string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	parenLevel := 0

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			// We keep the quotes in the parts to allow consistent trimming later
			current.WriteByte(c)
		case c == '(' && !inQuote:
			parenLevel++
			current.WriteByte(c)
		case c == ')' && !inQuote:
			parenLevel--
			current.WriteByte(c)
		case c == ' ' && !inQuote && parenLevel == 0:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func formatIMAPAddress(email string) string {
	email = strings.Trim(email, "<>")
	parts := strings.Split(email, "@")
	mailbox := email
	host := ""
	if len(parts) == 2 {
		mailbox = parts[0]
		host = parts[1]
	}
	// (display-name source-route mailbox-name hostname)
	return fmt.Sprintf("(NIL NIL %s %s)", quoteIMAP(mailbox), quoteIMAP(host))
}

func quoteIMAP(s string) string {
	if s == "" {
		return "NIL"
	}
	return fmt.Sprintf("\"%s\"", strings.ReplaceAll(s, "\"", "\\\""))
}

func formatIMAPAddressList(emails []string) string {
	if len(emails) == 0 {
		return "NIL"
	}
	var sb strings.Builder
	sb.WriteString("(")
	for i, email := range emails {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(formatIMAPAddress(email))
	}
	sb.WriteString(")")
	return sb.String()
}

func formatIMAPFlags(flags []string) string {
	return "(" + strings.Join(flags, " ") + ")"
}

func getHeader(fullBody, field string) string {
	parts := strings.SplitN(fullBody, "\r\n\r\n", 2)
	headerSection := parts[0]
	headerLines := strings.Split(headerSection, "\r\n")
	fieldLower := strings.ToLower(field) + ":"
	for i := 0; i < len(headerLines); i++ {
		line := headerLines[i]
		if strings.HasPrefix(strings.ToLower(line), fieldLower) {
			val := strings.TrimSpace(line[len(fieldLower):])
			// Handle folded lines
			for j := i + 1; j < len(headerLines); j++ {
				if len(headerLines[j]) > 0 && (headerLines[j][0] == ' ' || headerLines[j][0] == '\t') {
					val += " " + strings.TrimSpace(headerLines[j])
					i = j
				} else {
					break
				}
			}
			return val
		}
	}
	return ""
}

func extractHeaders(fullBody string, fields []string) string {
	parts := strings.SplitN(fullBody, "\r\n\r\n", 2)
	headerSection := parts[0]
	headerLines := strings.Split(headerSection, "\r\n")
	var filtered []string

	for _, field := range fields {
		fieldLower := strings.ToLower(field) + ":"
		for i := 0; i < len(headerLines); i++ {
			line := headerLines[i]
			if strings.HasPrefix(strings.ToLower(line), fieldLower) {
				filtered = append(filtered, line)
				for j := i + 1; j < len(headerLines); j++ {
					if len(headerLines[j]) > 0 && (headerLines[j][0] == ' ' || headerLines[j][0] == '\t') {
						filtered = append(filtered, headerLines[j])
						i = j
					} else {
						break
					}
				}
			}
		}
	}
	return strings.Join(filtered, "\r\n") + "\r\n\r\n"
}
