package webhook

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// VerifyGitHubSignature256 validates X-Hub-Signature-256 (sha256=...) per GitHub webhook docs.
func VerifyGitHubSignature256(body []byte, sigHeader, secret string) bool {
	if sigHeader == "" || secret == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	wantHex := strings.TrimPrefix(sigHeader, prefix)
	gotMAC, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(gotMAC, expected)
}

// VerifyGitHubSignature1 validates legacy X-Hub-Signature (sha1=...).
func VerifyGitHubSignature1(body []byte, sigHeader, secret string) bool {
	if sigHeader == "" || secret == "" {
		return false
	}
	const prefix = "sha1="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	wantHex := strings.TrimPrefix(sigHeader, prefix)
	gotMAC, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(gotMAC, expected)
}
