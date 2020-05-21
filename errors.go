package uciph

import "errors"

// ErrTooManyChunksEncrypted is returned when nonce counter is about to overflow.
// Usually it's returned to prevent xoring with same keystream again and prevent panicking.
var ErrTooManyChunksEncrypted = errors.New("uciph: This encryptor can't safely encrypt more chunks")

// ErrNonceInvalid is returned when nonce management code detects that there is problem with nonce.
var ErrNonceInvalid = errors.New("uciph: Input ciphertext has no nonce or it's invalid")

// ErrCiphertextInvalid is returned when ciphertext is corrupted
var ErrCiphertextInvalid = errors.New("uciph: Input ciphertext has invalid format or is corrupted")

// ErrKeyInvalid is returned when input data is not valid key or key is corrupted somewhere else.
var ErrKeyInvalid = errors.New("uciph: Input data is not valid key")

// ErrKeyTypeInvalid is returned when given type of key is not accepted in given context.
var ErrKeyTypeInvalid = errors.New("uciph: Invalid input key type")
