// Package onetime provides a business-agnostic store for expiring secrets
// that may be verified a limited number of times and consumed once.
package onetime

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"furtalk/internal/platform/cache"
)

var (
	// ErrAtomicUnsupported indicates that one-time storage was constructed
	// without the required narrow atomic backend.
	ErrAtomicUnsupported = errors.New("onetime: backend lacks atomic JSON comparison")
)

// Backend is the narrow storage contract required by Store. It intentionally
// excludes unrelated cache operations so a namespaced backend cannot be
// accidentally bypassed through a broad shared-store interface.
type Backend interface {
	Set(context.Context, string, any, time.Duration) error
	Delete(context.Context, string) error
	GetRawJSON(context.Context, string) (json.RawMessage, error)
	CompareAndSwapJSON(context.Context, string, json.RawMessage, json.RawMessage) (bool, error)
	CompareAndDeleteJSON(context.Context, string, json.RawMessage) (bool, error)
}

// VerifyResult describes the result of a verification attempt.
type VerifyResult uint8

const (
	// Consumed indicates a matching digest was accepted and the secret removed.
	Consumed VerifyResult = iota
	// Attempted indicates a non-matching digest was recorded as a failed attempt.
	Attempted
	// Invalid indicates a missing, expired, malformed, or exhausted secret.
	Invalid
)

// record is deliberately private. Its JSON field names remain stable so active
// records written by older versions remain readable during rolling deployment.
type record struct {
	Hash      string    `json:"hash"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store manages expiring, limited-attempt secrets on top of one cache backend.
// It does not own the backend's lifecycle or create another client/pool.
type Store struct {
	backend Backend
	now     func() time.Time
}

// New constructs a Store over an existing narrow backend. There is
// intentionally no read-modify-write fallback.
func New(backend Backend) (*Store, error) {
	if backend == nil {
		return nil, ErrAtomicUnsupported
	}
	return &Store{backend: backend, now: time.Now}, nil
}

// Issue stores or replaces a secret. The digest is opaque to this package;
// callers choose how to derive it and provide their business key.
func (s *Store) Issue(ctx context.Context, key, digest string, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.backend.Set(ctx, key, record{
		Hash:      digest,
		Attempts:  0,
		ExpiresAt: s.now().UTC().Add(ttl),
	}, ttl)
}

// Delete removes a secret. Missing keys are treated as success by the cache
// contract.
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.backend.Delete(ctx, key)
}

// VerifyAndConsume verifies a submitted digest and atomically applies the
// corresponding state transition. Stale CAS attempts are retried from a fresh
// read, so concurrent wrong submissions cannot lose increments and concurrent
// matching submissions can consume only once.
func (s *Store) VerifyAndConsume(ctx context.Context, key, submittedDigest string, maxAttempts int) (VerifyResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Invalid, err
		}
		raw, err := s.getRaw(ctx, key)
		if errors.Is(err, cache.ErrNotFound) {
			return Invalid, nil
		}
		if err != nil {
			return Invalid, err
		}

		var current record
		if err := json.Unmarshal(raw, &current); err != nil || !validRecord(current) {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}

		if !s.now().Before(current.ExpiresAt) || current.Attempts >= maxAttempts {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}

		if subtle.ConstantTimeCompare([]byte(current.Hash), []byte(submittedDigest)) == 1 {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Consumed, nil
			}
			continue
		}

		current.Attempts++
		if current.Attempts >= maxAttempts {
			ok, casErr := s.backend.CompareAndDeleteJSON(ctx, key, raw)
			if casErr != nil {
				return Invalid, casErr
			}
			if ok {
				return Invalid, nil
			}
			continue
		}
		replacement, marshalErr := json.Marshal(current)
		if marshalErr != nil {
			return Invalid, fmt.Errorf("onetime: encode record: %w", marshalErr)
		}
		ok, casErr := s.backend.CompareAndSwapJSON(ctx, key, raw, replacement)
		if casErr != nil {
			return Invalid, casErr
		}
		if ok {
			return Attempted, nil
		}
	}
}

func (s *Store) getRaw(ctx context.Context, key string) (json.RawMessage, error) {
	return s.backend.GetRawJSON(ctx, key)
}

func validRecord(value record) bool {
	return value.Hash != "" && value.Attempts >= 0 && !value.ExpiresAt.IsZero()
}

var _ interface {
	Issue(context.Context, string, string, time.Duration) error
	Delete(context.Context, string) error
	VerifyAndConsume(context.Context, string, string, int) (VerifyResult, error)
} = (*Store)(nil)
