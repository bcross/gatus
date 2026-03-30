package security

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/TwiN/gocache/v2"
)

var sessions = gocache.NewCache().WithEvictionPolicy(gocache.LeastRecentlyUsed) // TODO: Move this to storage

// SessionData contains the data stored in a session
type SessionData struct {
	Subject string
	Groups  []string
}

// SetWithTTL stores a session with subject and optional groups
func SetWithTTL(sessionID, subject string, ttl time.Duration, groups ...string) {
	data := SessionData{
		Subject: subject,
		Groups:  groups,
	}
	sessions.SetWithTTL(sessionID, data, ttl)
}

// Get retrieves the session data for a given session ID
func Get(sessionID string) (SessionData, bool) {
	value, exists := sessions.Get(sessionID)
	if !exists {
		return SessionData{}, false
	}
	data, ok := value.(SessionData)
	return data, ok
}

// HasGroup checks if the session has a specific group
func HasGroup(sessionID, group string) bool {
	data, exists := Get(sessionID)
	if !exists {
		return false
	}
	group = strings.ToLower(group)
	for _, g := range data.Groups {
		if strings.ToLower(g) == group {
			return true
		}
	}
	return false
}

// GenerateSessionID generates a random session ID using crypto/rand
func GenerateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback (should never happen)
		for i := range b {
			b[i] = byte(i)
		}
	}
	return base64.URLEncoding.EncodeToString(b)
}
