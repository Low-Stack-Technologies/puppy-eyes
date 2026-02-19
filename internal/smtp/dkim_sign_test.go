package smtp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignDKIMAddsHeader(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "dkim_key.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	DKIMKeyPath = keyPath
	DKIMSelector = "default"
	resetDKIMSigner()

	msg := "From: test@example.com\r\nTo: user@example.net\r\nSubject: Hi\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello"

	signed, err := SignDKIM(msg, "example.com")
	if err != nil {
		t.Fatalf("SignDKIM error: %v", err)
	}
	if !strings.HasPrefix(signed, "DKIM-Signature:") {
		t.Fatalf("expected DKIM-Signature at start")
	}
	if !strings.Contains(signed, "From: test@example.com") {
		t.Fatalf("expected original headers present")
	}
}

func TestSignDKIMSkipsExistingSignature(t *testing.T) {
	msg := "DKIM-Signature: test\r\nFrom: a@example.com\r\n\r\nBody"
	signed, err := SignDKIM(msg, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signed != msg {
		t.Fatalf("expected original message when DKIM-Signature exists")
	}
}

func TestSignDKIMMissingKey(t *testing.T) {
	DKIMKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	resetDKIMSigner()
	_, err := SignDKIM("From: a@example.com\r\n\r\nBody", "example.com")
	if err == nil {
		t.Fatalf("expected error for missing key")
	}
}
