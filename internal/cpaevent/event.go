package cpaevent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

const ReplayWindow = 5 * time.Minute

var (
	ErrInvalidSignature = errors.New("invalid CPA event signature")
	ErrExpiredSignature = errors.New("expired CPA event signature")
	ErrInvalidEvent     = errors.New("invalid CPA degradation event")
)

type Payload struct {
	EventID            uuid.UUID `json:"event_id"`
	CredentialID       string    `json:"credential_id"`
	CredentialRevision string    `json:"credential_revision"`
	Email              string    `json:"email"`
	ExpectedModel      string    `json:"expected_model"`
	DetectedModel      string    `json:"detected_model"`
	Confidence         float64   `json:"confidence"`
	ObservedAt         time.Time `json:"observed_at"`
	Status             string    `json:"status"`
}

func Verify(secret []byte, header http.Header, body []byte, now time.Time) (Payload, string, error) {
	timestamp := strings.TrimSpace(header.Get("X-CPA-Timestamp"))
	signature := strings.TrimSpace(header.Get("X-CPA-Signature"))
	eventHeader := strings.TrimSpace(header.Get("X-CPA-Event-ID"))
	observed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		var seconds int64
		if _, scanErr := fmt.Sscan(timestamp, &seconds); scanErr != nil {
			return Payload{}, "", ErrInvalidSignature
		}
		observed = time.Unix(seconds, 0).UTC()
	}
	if delta := now.Sub(observed); delta < -ReplayWindow || delta > ReplayWindow {
		return Payload{}, "", ErrExpiredSignature
	}
	provided, err := hex.DecodeString(signature)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp + "\n"))
	_, _ = mac.Write(body)
	if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		return Payload{}, "", ErrInvalidSignature
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var payload Payload
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || payload.EventID == uuid.Nil || eventHeader != payload.EventID.String() || !valid(payload) {
		return Payload{}, "", ErrInvalidEvent
	}
	return payload, strings.ToLower(strings.TrimSpace(payload.Email)), nil
}

func valid(payload Payload) bool {
	address, err := mail.ParseAddress(strings.TrimSpace(payload.Email))
	return err == nil && strings.EqualFold(address.Address, strings.TrimSpace(payload.Email)) &&
		validLength(payload.CredentialID, 1, 512) && validLength(payload.CredentialRevision, 1, 256) &&
		validLength(payload.ExpectedModel, 1, 200) && validLength(payload.DetectedModel, 1, 200) &&
		payload.Confidence >= 0 && payload.Confidence <= 1 && !payload.ObservedAt.IsZero() && payload.Status == "quarantined"
}

func validLength(value string, minimum, maximum int) bool {
	length := len([]rune(value))
	return length >= minimum && length <= maximum
}
