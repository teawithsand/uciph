package uciph

import "errors"

// ErrTooManyChunksEncrypted is returned when nonce counter is about to overflow.
// Usually it's returned to prevent xoring with same keystream again and prevent panicking.
var ErrTooManyChunksEncrypted = errors.New("uciph: This encryptor can't safely encrypt more chunks")

// ErrNonceInvalid is returned when nonce management code detects that there is problem with nonce.
var ErrNonceInvalid = errors.New("uciph: Input ciphertext has no nonce or it's invalid")

var ErrKeyInvalid = errors.New("uciph: Input data is not valid key")
