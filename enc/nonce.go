package enc

// NonceMode sets how nonces should be generated if cipher needs any.
type NonceMode uint32

const (
	// NonceModeDefault is default nonce mode.
	NonceModeDefault NonceMode = NonceModeRandom

	// NonceModeRandom generates random nonces for specified cipher.
	// It reutrns error if too many ciphertexts are created using this method.
	// For instance for 12 byte nonce limit is 2**32 ciphertexts.
	NonceModeRandom NonceMode = 1

	// NonceModeRandomUnsafe generates random nonce, just like NonceModeRandom
	// but does not fail after some amount of ciphertexts generated.
	//
	// Right now it's not implemented and behaves like NonceModeRandom.
	NonceModeRandomUnsafe NonceMode = 3

	// NonceModeCounter uses NonceCounter in order to generate unique nonces.
	// It returns errors if NonceCouter has overflown and would generate not unique nonces.
	NonceModeCounter NonceMode = 2
)

// NonceModeOptions specifies options, which have NonceMode setting.
type NonceModeOptions interface {
	NonceMode() NonceMode
}

// GetNonceMode gets nonce mode from specified options.
func GetNonceMode(options interface{}) (nm NonceMode) {
	nm = NonceModeDefault
	if nopts, ok := options.(NonceModeOptions); ok {
		nm = nopts.NonceMode()
	}
	return
}
