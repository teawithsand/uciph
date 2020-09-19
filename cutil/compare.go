package cutil

import (
	"crypto/hmac"
)

// There is hmac.Equal function

// ConstantTimeCompare checks if two slices are equal and returns true if they are, false otherwise.
// It uses constant-time comparison.
// It's not contant time when len(d1) != len(d2)
func ConstantTimeCompare(d1, d2 []byte) bool {
	return hmac.Equal(d1, d2)
}
