package util

import (
	"errors"
	"fmt"
	"unicode"
)

const (
	// LabelHostnameLength is the maximum length for a DNS label,
	// value related to RFC 1123 and 952.
	LabelHostnameLength = 63
)

// DNS validation errors. Hostname-side validation lives on
// `tailscale.com/util/dnsname` and the state's given-name collision handling; only
// the username-side errors stay in this package.
var (
	ErrUsernameTooShort        = errors.New("username must be at least 2 characters long")
	ErrUsernameMustStartLetter = errors.New("username must start with a letter")
	ErrUsernameTooManyAt       = errors.New("username cannot contain more than one '@'")
	ErrUsernameInvalidChar     = errors.New("username contains invalid character")
)

// ValidateUsername checks if a username is valid.
// It must be at least 2 characters long, start with a letter, and contain
// only letters, numbers, hyphens, dots, and underscores.
// It cannot contain more than one '@'.
// It cannot contain invalid characters.
func ValidateUsername(username string) error {
	// Ensure the username meets the minimum length requirement
	if len(username) < 2 {
		return ErrUsernameTooShort
	}

	// Ensure the username starts with a letter
	if !unicode.IsLetter(rune(username[0])) {
		return ErrUsernameMustStartLetter
	}

	atCount := 0

	for _, char := range username {
		switch {
		case unicode.IsLetter(char),
			unicode.IsDigit(char),
			char == '-',
			char == '.',
			char == '_':
			// Valid characters
		case char == '@':
			atCount++
			if atCount > 1 {
				return ErrUsernameTooManyAt
			}
		default:
			return fmt.Errorf("%w: '%c'", ErrUsernameInvalidChar, char)
		}
	}

	return nil
}
