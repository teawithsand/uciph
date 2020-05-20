package uciph

import (
	"crypto/rand"
	"io"
)

// DefaultRNG returns default RNG.
// It's used when it's required and not provided in options.
var DefaultRNG io.Reader = rand.Reader

// RNGOptions is kind of options, which provides custom RNG
type RNGOptions interface {
	RNG() io.Reader
}

// GetRNG returns RNG from options or DefaultRNG.
func GetRNG(options interface{}) (rng io.Reader) {
	ropt, ok := options.(RNGOptions)
	if ok {
		rng = ropt.RNG()
	}
	if rng == nil {
		rng = DefaultRNG
	}
	return
}
