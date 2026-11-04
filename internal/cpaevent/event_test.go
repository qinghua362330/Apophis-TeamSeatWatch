package cpaevent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"
)

const contractBody = `{"event_id":"9e8d05ef-4e21-43a0-9320-73789ebcc4da","credential_id":"credential-1","credential_revision":"revision-1","email":"User@Example.com","expected_model":"gpt-6.1-sol","detected_model":"gpt-6-luna","confidence":0.97,"observed_at":"2026-11-04T02:00:00Z","status":"quarantined"}`

func contractHeaders(secret, timestamp string, body []byte) http.Header {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "\n"))
	_, _ = mac.Write(body)
	header := http.Header{}
	header.Set("X-CPA-Event-ID", "9e8d05ef-4e21-43a0-9320-73789ebcc4da")
	header.Set("X-CPA-Timestamp", timestamp)
	header.Set("X-CPA-Signature", hex.EncodeToString(mac.Sum(nil)))
	return header
}

func TestVerifyCPAContract(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	body := []byte(contractBody)
	now := time.Date(2026, 11, 4, 2, 0, 30, 0, time.UTC)
	header := contractHeaders(secret, "1793757600", body)
	payload, email, err := Verify([]byte(secret), header, body, now)
	if err != nil || payload.CredentialID != "credential-1" || email != "user@example.com" {
		t.Fatalf("payload=%+v email=%q err=%v", payload, email, err)
	}

	invalid := header.Clone()
	invalid.Set("X-CPA-Signature", "00")
	if _, _, err = Verify([]byte(secret), invalid, body, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid signature err=%v", err)
	}

	stale := contractHeaders(secret, "1793757000", body)
	if _, _, err = Verify([]byte(secret), stale, body, now); !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("stale err=%v", err)
	}

	mismatch := header.Clone()
	mismatch.Set("X-CPA-Event-ID", "004f649c-842c-4ff1-a224-3e74125009c8")
	if _, _, err = Verify([]byte(secret), mismatch, body, now); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("mismatch err=%v", err)
	}
}
