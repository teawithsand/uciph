package sig

import (
	"crypto"
	"crypto/hmac"
	"hash"

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

// NewCryptoHasherFac creates HasherFactory form golang's std hash.Hash
// for instance hash.SHA256.
func NewCryptoHasherFac(h crypto.Hash) (fac HasherFac, err error) {
	if !h.Available() {
		err = uciph.ErrHashNotAvailable
		return
	}

	fac = HasherFacFunc(func(options interface{}) (Hasher, error) {
		return &stlHasher{
			hash: h.New(),
		}, nil
	})
	return
}

// NewHMACKeyParser creates HMACKeyParser for specified hash algorithm.
func NewHMACKeyParser(h crypto.Hash) (parser MACKeyParser, err error) {
	if !h.Available() {
		err = uciph.ErrHashNotAvailable
		return
	}

	parser = MACKeyParserFunc(func(data []byte) (MACKey, error) {
		return MACKeyFunc(func(options interface{}) (Hasher, error) {
			return &stlHasher{
				hash: hmac.New(h.New, data),
			}, nil
		}), nil
	})
	return
}

type stlHasher struct {
	hash hash.Hash
}

func (h *stlHasher) Write(d []byte) (sz int, err error) {
	return h.hash.Write(d)
}

func (h *stlHasher) Sum(appendTo []byte) (res []byte, err error) {
	res = h.hash.Sum(appendTo)
	return
}
