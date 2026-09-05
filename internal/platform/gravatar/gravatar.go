// Package gravatar implements the Gravatar URL protocol without product policy.
package gravatar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"furtalk/internal/platform/urlx"
)

// ErrInvalidBaseURL reports an invalid configured Gravatar-compatible base URL.
var ErrInvalidBaseURL = errors.New("gravatar: invalid base url")

// ValidateBaseURL validates an absolute HTTP(S) avatar base without credentials,
// query parameters, or a fragment.
func ValidateBaseURL(raw string) error {
	if _, err := urlx.ParseHTTPBase(raw); err != nil {
		return fmt.Errorf("%w: must be an absolute url", ErrInvalidBaseURL)
	}
	return nil
}

// URL derives a Gravatar-compatible avatar URL from a normalized email.
func URL(normalizedEmail, baseURL string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(normalizedEmail))))
	base, err := urlx.ParseHTTPBase(baseURL)
	if err != nil {
		return ""
	}
	return urlx.JoinPathSegments(base, hex.EncodeToString(sum[:])).String()
}
