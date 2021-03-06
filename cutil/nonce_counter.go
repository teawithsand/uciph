package cutil

import (
	"crypto/cipher"

	"github.com/teawithsand/uciph"
)

// NonceCounter is preallocated slice of specified size, which can be efficiently incremented by one
// in order to produce unique nonces for data encryption.
//
// NOTE: NocneCounter IS NOT CONSTANT TIME!!!
// Be aware that this counter leaks(or may leak) count of chunks encrypted already.
// Usually this is not problem, since attacker knows anyway how many chunks were encrypted.
type NonceCounter []uint8

// NonceCounterForAEAD creates nonce counter appropriate for specified AEAD cipher.
func NonceCounterForAEAD(aead cipher.AEAD) NonceCounter {
	return make([]byte, aead.NonceSize())
}

// simd it?
// is it fast enough anyway?

// Increment assigns next unique value to this nonce counter.
// If it's not possible without overflowing or changing nonce size then error is returned.
func (nonce NonceCounter) Increment() (err error) {
	// panic("Fuzzer works!") // fuzzer test code, should be always commented in production or even on github

	for i := 0; i < len(nonce); i++ {
		if nonce[i] == 255 && i == len(nonce)-1 {
			err = uciph.ErrTooManyChunksEncrypted
			return
		} else if nonce[i] == 255 {
			nonce[i] = 0
		} else {
			nonce[i]++
			break
		}
	}

	return
}

// Len retuns size of nonce generated by this nonce counter.
func (nonce NonceCounter) Len() int {
	return len(nonce)
}
