package mobile

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Test hooks: never set in production (no flag reaches them).

// CheckEndpoint is checkEndpoint.
func CheckEndpoint(raw string) error { _, err := checkEndpoint(raw); return err }

// SetPushTransport makes s push with client to the endpoints allow
// accepts, with interval between rounds.
func SetPushTransport(s *Service, client *http.Client, allow func(string) (*url.URL, error), interval time.Duration) {
	s.push.client, s.push.allow, s.push.interval = client, allow, interval
}

// VAPIDToken is the VAPID JWT s sends to aud.
func VAPIDToken(s *Service, aud string, now time.Time) (string, error) {
	return s.push.vapidToken(aud, now)
}

// VAPIDPublic is the applicationServerKey (base64url).
func VAPIDPublic(s *Service) string { return s.push.pub }

// PushAll runs one round of pushes now.
func PushAll(ctx context.Context, s *Service) { s.pushAll(ctx) }
