package sig

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"io"

	"github.com/teawithsand/uciph"
)

// There is hmac.Equal function
/*
// VerifyDigestEqual checs if two slices are equal using constant time algorithm.
// It should be used in favour of bytes.Compare when comparing digests.
func VerifyDigestEqual(d1, d2 []byte) bool {
	return subtle.ConstantTimeCompare(d1, d2) == 1
}
*/

// HasherFac is something, which creates hasher.
// It's also used for HMAC.
type HasherFac = func(options interface{}) (Hasher, error)

// Hasher is something capable of computing hashes.
// It accepts data and creates hash sum form it.
type Hasher interface {
	io.Writer

	Finalize(appendTo []byte) (res []byte, err error)
}

// NewCryptoHasherFac creates HasherFac form golang's std hash.Hash
// for instance hash.SHA256.
func NewCryptoHasherFac(h crypto.Hash) (fac HasherFac, err error) {
	if !h.Available() {
		err = uciph.ErrHashNotAvailable
		return
	}

	fac = HasherFac(func(options interface{}) (Hasher, error) {
		return &stlHasher{
			hash: h.New(),
		}, nil
	})
	return
}

// NewHMAC creates HasherFac from golang's std hash.Hash and key.
func NewHMAC(h crypto.Hash, key []byte) (fac HasherFac, err error) {
	if !h.Available() {
		err = uciph.ErrHashNotAvailable
		return
	}

	fac = HasherFac(func(options interface{}) (Hasher, error) {
		return &stlHasher{
			hash: hmac.New(h.New, key),
		}, nil
	})
	return
}

type stlHasher struct {
	hash hash.Hash
}

func (h *stlHasher) Write(d []byte) (sz int, err error) {
	return h.hash.Write(d)
}

func (h *stlHasher) Finalize(appendTo []byte) (res []byte, err error) {
	res = h.hash.Sum(appendTo)
	return
}
