package rand

import (
	"crypto/rand"
	"io"
	mrand "math/rand"

	"github.com/teawithsand/uciph"
	"golang.org/x/crypto/chacha20"
)

// PRNGFactory is function, which creates RNG from seed.
type PRNGFactory func(seed []byte) (RNG, error)

// RNG is extension for any io.Reader, which is RNG.
// USE WITH CAUTION, IN ORDER NOT TO WRAP INVALID READER AS RNG!!!
type RNG io.Reader

/*
// ReadFull is shortcut for io.ReadFull
func (r RNG) ReadFull(buf []byte) (sz int, err error) {
	return io.ReadFull(r, buf)
}

// ReadUint32 reads arbitrary int from RNG.
func (r RNG) ReadUint32() (v uint32, err error) {
	var b [4]byte
	_, err = r.ReadFull(b[:])
	if err != nil {
		return
	}
	v = binary.BigEndian.Uint32(b[:])
	return
}

// TODO(teawithsand): more extension methods for RNG AFTER making rng structure wrapping interface
*/

// ZeroRNG is fake RNG which yields zeros only.
// IT'S HACK!!! DO NOT USE FOR ANY LEGITIMATE REASON!!!
func ZeroRNG() RNG {
	return readerFunc(func(buf []byte) (int, error) {
		for i := range buf {
			buf[i] = 0
		}
		return len(buf), nil
	})
}

// DefaultRNG returns default RNG.
// It's used when it's required and not provided in options.
func DefaultRNG() RNG {
	return rand.Reader
}

// FastRNG creates NewSource from math/rand form golang STL.
// This RNG IS NOT cryptographically secure and SHOULD NOT be used for crypto.
func FastRNG(seed int64) RNG {
	return mrand.New(mrand.NewSource(seed))
}

// RNGOptions is kind of options, which provides custom RNG.
type RNGOptions interface {
	GetRNG() RNG
}

// GetRNG returns RNG from options or DefaultRNG.
func GetRNG(options interface{}) (rng RNG) {
	ropt, ok := options.(RNGOptions)
	if ok {
		rng = ropt.GetRNG()
	}
	if rng == nil {
		rng = DefaultRNG()
	}
	return
}

// NewChaCha20RNG creates ChaCha20 based RNG from specified seed.
// Seed has to be 32 bytes long.
// It can be extended with hash function if needed.
func NewChaCha20RNG(seed []byte) (res RNG, err error) {
	if len(seed) != 32 {
		// TODO(teawithsand): some error
		err = uciph.ErrInvalidKeySize
		return
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
		// fill with zeros
		// and xor with keystream
		sz = len(b)
		for i := range b {
			b[i] = 0
		}

		// TDOO(teawithsand): implement error rather than panicking once too many data gets extracted
		c.XORKeyStream(b[:], b[:])
		return
	})
	return
}
