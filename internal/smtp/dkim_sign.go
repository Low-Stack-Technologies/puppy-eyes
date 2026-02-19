package smtp

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/emersion/go-msgauth/dkim"
)

var (
	DKIMKeyPath     = "certs/dkim/dkim_private.pem"
	DKIMSelector    = "default"
	DKIMHeaderKeys  = []string{"From", "To", "Subject", "Date", "Message-ID"}
	dkimSignerOnce  sync.Once
	dkimSigner      crypto.Signer
	dkimSignerError error
)

func init() {
	if value := strings.TrimSpace(os.Getenv("DKIM_KEY_PATH")); value != "" {
		DKIMKeyPath = value
	}
	if value := strings.TrimSpace(os.Getenv("DKIM_SELECTOR")); value != "" {
		DKIMSelector = value
	}
	if value := strings.TrimSpace(os.Getenv("DKIM_HEADER_KEYS")); value != "" {
		DKIMHeaderKeys = splitHeaderKeys(value)
	}
}

func SignDKIM(rawMessage string, domain string) (string, error) {
	if hasDKIMSignature(rawMessage) {
		return rawMessage, nil
	}

	signer, err := loadDKIMSigner()
	if err != nil {
		return "", err
	}

	domain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(domain), "."))
	if domain == "" {
		return "", errors.New("dkim: empty signing domain")
	}

	options := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               DKIMSelector,
		Signer:                 signer,
		HeaderKeys:             DKIMHeaderKeys,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}

	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(rawMessage), options); err != nil {
		return "", err
	}
	return out.String(), nil
}

func loadDKIMSigner() (crypto.Signer, error) {
	dkimSignerOnce.Do(func() {
		file, err := os.Open(DKIMKeyPath)
		if err != nil {
			dkimSignerError = fmt.Errorf("dkim: failed to open key file: %w", err)
			return
		}
		defer file.Close()

		keyData, err := io.ReadAll(file)
		if err != nil {
			dkimSignerError = fmt.Errorf("dkim: failed to read key file: %w", err)
			return
		}

		signer, err := parseDKIMPrivateKey(keyData)
		if err != nil {
			dkimSignerError = err
			return
		}
		dkimSigner = signer
	})

	if dkimSignerError != nil {
		return nil, dkimSignerError
	}
	if dkimSigner == nil {
		return nil, errors.New("dkim: signer not initialized")
	}
	return dkimSigner, nil
}

func parseDKIMPrivateKey(keyData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("dkim: failed to decode PEM key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case crypto.Signer:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("dkim: unsupported private key format")
}

func hasDKIMSignature(rawMessage string) bool {
	headers := rawMessage
	if idx := strings.Index(rawMessage, "\r\n\r\n"); idx != -1 {
		headers = rawMessage[:idx]
	} else if idx := strings.Index(rawMessage, "\n\n"); idx != -1 {
		headers = rawMessage[:idx]
	}

	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "dkim-signature:") {
			return true
		}
	}
	return false
}

func resetDKIMSigner() {
	dkimSignerOnce = sync.Once{}
	dkimSigner = nil
	dkimSignerError = nil
}

func splitHeaderKeys(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{})
	var keys []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = canonicalHeaderKey(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		keys = append(keys, part)
	}
	if len(keys) == 0 {
		return DKIMHeaderKeys
	}
	return keys
}

func canonicalHeaderKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	parts := strings.Split(strings.ToLower(key), "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "-")
}

var _ = rsa.PrivateKey{}
