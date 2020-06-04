package sig

import (
	"crypto"
	_ "crypto/sha512"
)

// DefaultSigningHasherFac contains default HasherFac used
// for shortening messages before signing them.
var defaultSigningHasherFac = mustOk(NewCryptoHasherFac(
	crypto.SHA512,
)).(HasherFac)

func mustOk(v interface{}, err error) interface{} {
	if err != nil {
		panic(err)
	}
	return v
}

// DefaultSginingHasherFac gets default hasher factory, which should be used for shortening messages for signing purposes.
func DefaultSginingHasherFac() HasherFac {
	return defaultSigningHasherFac
}

// SetDefaultSigningHasherFac sets hasher factory, which is used by default for signing purposes.
// Note: This function is not thread safe.
func SetDefaultSigningHasherFac(fac HasherFac) {
	defaultSigningHasherFac = fac
}
