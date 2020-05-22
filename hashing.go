package uciph

import (
	"crypto"
	"crypto/hmac"
	"hash"
)

// There is hmac.Equal function
/*
// VerifyDigestEqual checs if two slices are equal using constant time algorithm.
// It should be used in favour of bytes.Compare when comparing digests.
func VerifyDigestEqual(d1, d2 []byte) bool {
	return subtle.ConstantTimeCompare(d1, d2) == 1
}
*/

// NewCryptoHasherFactory creates HasherFactory form golang's std hash.Hash
// for instance hash.SHA256.
func NewCryptoHasherFactory(h crypto.Hash) (fac HasherFactory, err error) {
	if !h.Available() {
		err = ErrHashNotAvailable
		return
	}

	fac = HasherFactoryFunc(func(options HasherOptions) (Hasher, error) {
		return &stlHasher{
			hash: h.New(),
		}, nil
	})
	return
}

// NewHMACKeyParser creates HMACKeyParser for specified hash algorithm.
func NewHMACKeyParser(h crypto.Hash) (parser HMACKeyParser, err error) {
	if !h.Available() {
		err = ErrHashNotAvailable
		return
	}

	parser = HMACKeyParserFunc(func(data []byte) (ParsedHMACKey, error) {
		return ParsedHMACKeyFunc(func(options HasherOptions) (Hasher, error) {
			return &stlHasher{
				hash: hmac.New(func() hash.Hash {
					return h.New()
				}, data),
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
