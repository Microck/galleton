package core

import (
	"encoding/json"
	"time"
)

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() { return nil }
	return &t
}

// Keep time.Time internally and preserve the stored schema while omitting
// absent timestamps on the wire, including on Go 1.23.
func (s State) MarshalJSON() ([]byte, error) {
	type plain State
	return json.Marshal(struct {
		*plain
		LastRefresh *time.Time `json:"last_refresh,omitempty"`
		NextRefresh *time.Time `json:"next_refresh,omitempty"`
		AccessExpiresAt *time.Time `json:"access_expires_at,omitempty"`
	}{(*plain)(&s), optionalTime(s.LastRefresh), optionalTime(s.NextRefresh), optionalTime(s.AccessExpiresAt)})
}

func (s Metadata) MarshalJSON() ([]byte, error) {
	type plain Metadata
	return json.Marshal(struct {
		*plain
		LastRefresh *time.Time `json:"last_refresh,omitempty"`
		NextRefresh *time.Time `json:"next_refresh,omitempty"`
		AccessExpiresAt *time.Time `json:"access_expires_at,omitempty"`
	}{(*plain)(&s), optionalTime(s.LastRefresh), optionalTime(s.NextRefresh), optionalTime(s.AccessExpiresAt)})
}

func (p Problem) MarshalJSON() ([]byte, error) {
	type plain Problem
	return json.Marshal(struct {
		*plain
		RetryAt *time.Time `json:"retry_at,omitempty"`
	}{(*plain)(&p), optionalTime(p.RetryAt)})
}

func (h HeadersResult) MarshalJSON() ([]byte, error) {
	type plain HeadersResult
	return json.Marshal(struct {
		*plain
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}{(*plain)(&h), optionalTime(h.ExpiresAt)})
}
