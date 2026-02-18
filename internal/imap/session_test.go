package imap

import (
	"strings"
	"testing"
)

func TestGetCapabilities(t *testing.T) {
	session := &imapSession{isTLS: false}
	caps := session.getCapabilities()
	if !strings.Contains(caps, "STARTTLS") {
		t.Errorf("Expected STARTTLS in non-TLS capabilities, got %s", caps)
	}
	if !strings.Contains(caps, "LOGINDISABLED") {
		t.Errorf("Expected LOGINDISABLED in non-TLS capabilities, got %s", caps)
	}
	if strings.Contains(caps, "AUTH=PLAIN") {
		t.Errorf("Did not expect AUTH=PLAIN in non-TLS capabilities, got %s", caps)
	}

	session.isTLS = true
	caps = session.getCapabilities()
	if strings.Contains(caps, "STARTTLS") {
		t.Errorf("Did not expect STARTTLS in TLS capabilities, got %s", caps)
	}
	if strings.Contains(caps, "LOGINDISABLED") {
		t.Errorf("Did not expect LOGINDISABLED in TLS capabilities, got %s", caps)
	}
	if !strings.Contains(caps, "AUTH=PLAIN") {
		t.Errorf("Expected AUTH=PLAIN in TLS capabilities, got %s", caps)
	}
}
