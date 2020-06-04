package sig

import "bytes"

// SigningHasherOptions denotates options, which have hasher designed for
// signing provided instead of default one.
type SigningHasherOptions interface {
	SigningHasher() Hasher
}

// GetSigningHasher retrives hasher designed to be used for signing purposes
// from options given.
func GetSigningHasher(options interface{}) (h Hasher, err error) {
	if hopt, ok := options.(SigningHasherOptions); ok {
		h = hopt.SigningHasher()
	} else {
		// note: hasher signer is default as it's more foolproof
		// and it allows streamming signing of large data chunks
		// unlike bufSigner which would kill program with OOM.
		h, err = DefaultSginingHasherFac().NewHasher(nil)
	}
	return
}

type hashSigner struct {
	hasher Hasher
	doSign func(hash, appendTo []byte) (res []byte, err error)
}

func (hs *hashSigner) Write(data []byte) (sz int, err error) {
	sz, err = hs.hasher.Write(data)
	return
}

func (hs *hashSigner) Sign(appendTo []byte) ([]byte, error) {
	// localBuffer prevents heap allocation for small hash sizes
	// when variable does not escape in doSign
	var localBuffer [64]byte
	sum, err := hs.hasher.Sum(localBuffer[:0])
	if err != nil {
		return appendTo, nil
	}
	return hs.doSign(sum, appendTo)
}

type bufferSigner struct {
	buf *bytes.Buffer

	// note: do sign must not modify data provided
	// should it be noted more explicitly?
	// surely it's not default behaviour and modifying it would
	// be strange
	doSign func(data, appendTo []byte) (res []byte, err error)
}

func (bs *bufferSigner) Write(data []byte) (sz int, err error) {
	return bs.buf.Write(data)
}

func (bs *bufferSigner) Sign(appendTo []byte) (res []byte, err error) {
	return bs.doSign(bs.buf.Bytes(), appendTo)
}

type hashVerifier struct {
	hasher   Hasher
	doVerify func(data, sign []byte) error
}

func (hv *hashVerifier) Write(data []byte) (sz int, err error) {
	sz, err = hv.hasher.Write(data)
	return
}

func (hv *hashVerifier) Verify(sign []byte) error {
	// localBuffer prevents heap allocation for small hash sizes
	// when variable does not escape in doSign
	var localBuffer [64]byte
	sum, err := hv.hasher.Sum(localBuffer[:0])
	if err != nil {
		return nil
	}
	return hv.doVerify(sum, sign)
}

type bufferVerifier struct {
	buf *bytes.Buffer

	// note: doVerify must not modify data provided
	doVerify func(data, sign []byte) error
}

func (bs *bufferVerifier) Write(data []byte) (sz int, err error) {
	return bs.buf.Write(data)
}

func (bs *bufferVerifier) Verify(sign []byte) error {
	return bs.doVerify(bs.buf.Bytes(), sign)
}
