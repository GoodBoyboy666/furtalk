// Package gravatar implements the Gravatar URL protocol without product policy.
package gravatar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalidBaseURL reports an invalid configured Gravatar-compatible base URL.
var ErrInvalidBaseURL = errors.New("gravatar: invalid base url")

// ValidateBaseURL validates an absolute HTTP(S) avatar base without credentials,
// query parameters, or a fragment.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: must be an absolute url", ErrInvalidBaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: must use http or https", ErrInvalidBaseURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: userinfo, query and fragment are forbidden", ErrInvalidBaseURL)
	}
	return nil
}

// URL derives a Gravatar-compatible avatar URL from a normalized email.
func URL(normalizedEmail, baseURL string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(normalizedEmail))))
	return strings.TrimRight(baseURL, "/") + "/" + hex.EncodeToString(sum[:])
}
