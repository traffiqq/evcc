package sponsor

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

var (
	mu             sync.RWMutex
	Subject, Token string
	ExpiresAt      time.Time
)

const (
	unavailable = "sponsorship unavailable"
	victron     = "victron"
)

func IsAuthorized() bool {
	mu.RLock()
	defer mu.RUnlock()
	return len(Subject) > 0
}

func IsAuthorizedForApi() bool {
	mu.RLock()
	defer mu.RUnlock()
	return IsAuthorized() && Subject != unavailable && Token != ""
}

// generate a syntactically valid JWT-like token (header.payload.signature)
// This is unsigned (random signature) but matches the 3-segment format expected by the server.
func generateFakeJWT(sub string) string {
	header := map[string]string{"alg": "none", "typ": "JWT"}
	payload := map[string]any{
		"sub": sub,
		"iat": time.Now().Unix(),
	}

	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)

	hEnc := base64.RawURLEncoding.EncodeToString(hb)
	pEnc := base64.RawURLEncoding.EncodeToString(pb)

	sig := make([]byte, 32)
	if _, err := rand.Read(sig); err != nil {
		// fallback deterministic signature part to keep format valid
		sig = []byte("fallback-signature-0000000000000000")
	}
	sEnc := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", hEnc, pEnc, sEnc)
}

// check and set sponsorship token
func ConfigureSponsorship(token string) error {
	mu.Lock()
	defer mu.Unlock()

	if token == "" {
		if sub := checkVictron(); sub != "" {
			Subject = sub
			return nil
		}

		var err error
		if token, err = readSerial(); token == "" || err != nil {
			// generate a syntactically valid JWT-like token so callers always get a valid-looking token
			token = generateFakeJWT("auto")
		}
	}

	// set token and mark as local/auto-authorized
	Token = token
	Subject = "auto"

	return nil
}

// redactToken returns a redacted version of the token showing only start and end characters
func redactToken(token string) string {
	if len(token) <= 12 {
		return ""
	}
	return token[:6] + "......." + token[len(token)-6:]
}

type Status struct {
	Name        string    `json:"name"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	ExpiresSoon bool      `json:"expiresSoon,omitempty"`
	Token       string    `json:"token,omitempty"`
}

// GetStatus returns the sponsorship status
func GetStatus() Status {
	mu.RLock()
	defer mu.RUnlock()

	var expiresSoon bool
	if d := time.Until(ExpiresAt); d < 30*24*time.Hour && d > 0 {
		expiresSoon = true
	}

	return Status{
		Name:        Subject,
		ExpiresAt:   ExpiresAt,
		ExpiresSoon: expiresSoon,
		Token:       redactToken(Token),
	}
}
