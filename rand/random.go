package rand

import (
	"crypto/rand"
	"io"
	mrand "math/rand"

	"golang.org/x/crypto/chacha20"
)

// TODO(teawithsand): make DefaultRNG function

// ZeroRNG is fake RNG which yields zeros only.
// IT'S HACK!!! DO NOT USE FOR ANY LEGITIMATE REASON!!!
func ZeroRNG() io.Reader {
	return readerFunc(func(buf []byte) (int, error) {
		for i := range buf {
			buf[i] = 0
		}
		return len(buf), nil
	})
}

// DefaultRNG returns default RNG.
// It's used when it's required and not provided in options.
func DefaultRNG() io.Reader {
	return rand.Reader
}

// FastRNG creates NewSource from math/rand form golang STL.
// This RNG IS NOT cryptographically secure and SHOULD NOT be used for crypto.
func FastRNG(seed int64) io.Reader {
	return mrand.New(mrand.NewSource(seed))
}

// RNGOptions is kind of options, which provides custom RNG.
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
		rng = DefaultRNG()
	}
	return
}

type readerFunc func(buf []byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) {
	return f(b)
}

// NewChaCha20RNG creates ChaCha20 based RNG from specified seed.
// Seed has to be 32 bytes long.
func NewChaCha20RNG(seed []byte) (res io.Reader, err error) {
	if len(seed) != 32 {
		// TODO(teawithsand): some error
	}

	nonce := []byte{ // nonce does not really matter
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	c, err := chacha20.NewUnauthenticatedCipher(seed, nonce)
	if err != nil {
		return
	}
	res = readerFunc(func(b []byte) (sz int, err error) {
		sz = len(b)
		for i := range b {
			b[i] = 0
		}

		// TDOO(teawithsand): implement error rather than panicking once
		c.XORKeyStream(b[:], b[:])
		return
	})
	return
}

/*
// RandBytes reads sz bytes from given reader.
// It's designed to fail if reading is interrupted. No partial reads are allowed.
// It's designed to be used with RNGs.
func RandBytes(r io.Reader, sz int) ([]byte, error) {
	res := make([]byte, sz)
	_, err := io.ReadFull(r, res[:])
	if err != nil {
		return nil, err
	}
	return res, nil
}
*/
