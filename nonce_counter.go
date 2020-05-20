package uciph

// NonceCounter is preallocated slice of specified size, which can be efficiently incremented by one
// in order to produce unique nonces for data encryption
type NonceCounter []uint8

// simd it?
// is it fast enough anyway?
func (nonce NonceCounter) Increment() (err error) {
	for i := 0; i < len(nonce); i++ {
		if nonce[i] == 255 && i == len(nonce)-1 {
			err = ErrTooManyChunksEncrypted
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
