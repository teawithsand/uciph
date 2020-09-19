package kx

// Generated contains public and secret part of key to KX algorithm.
type Generated struct {
	PublicPart []byte
	SecretPart []byte
}

// Gen generates key excahnge secret and pubic part.
// It appends to values in Generated struct.
type Gen = func(options interface{}, res *Generated) (err error)

// KX performs key exchange from given public and secret key(it parses them first).
// Result bytes(algorithm-dependent) are appended to res.
//
// Max byte count can be set with appropriate options. TODO(teawithsand): implement it
type KX func(options interface{}, public, secret, res []byte) (dst []byte, err error)
