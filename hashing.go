package uciph

import (
	"crypto"
	"hash"
)

// NewCryptoHasherFactory creates HasherFactory form golang's std hash.Hash
// for instance hash.SHA256.
func NewCryptoHasherFactory(h crypto.Hash) (fac HasherFactory, err error) {
	if !h.Available(){
		err = ErrHashNotAvailable
		return
	}
	fac = HasherFactoryFunc(func(options HasherOptions) Hasher {
		return &stlHasher{
			hash: h.New(),
		}
	})
	return 
}	

type stlHasher struct {
	hash hash.Hash
}

func(h *stlHasher) Write(d []byte) (sz int, err error) {
	return h.hash.Write(d)
}
func(h *stlHasher) Sum(appendTo []byte) (res []byte, err error){
	res = h.hash.Sum(appendTo)
	return
}