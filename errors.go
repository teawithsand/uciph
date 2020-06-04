package uciph

import "errors"

// TODO(teawithsand): remove non-common errors from there

// ErrNonceInvalid is returned when nonce management code detects that there is problem with nonce.
var ErrNonceInvalid = errors.New("uciph: Input ciphertext has no nonce or it's invalid")

// ErrCiphertextInvalid is returned when ciphertext is corrupted
var ErrCiphertextInvalid = errors.New("uciph: Input ciphertext has invalid format or is corrupted")

// ErrKeyInvalid is returned when input data is not valid key or key is corrupted somewhere else.
var ErrKeyInvalid = errors.New("uciph: Input data is not valid key")

// ErrKeyTypeInvalid is returned when given type of key is not accepted in given context.
var ErrKeyTypeInvalid = errors.New("uciph: Invalid input key type")

// ErrHashNotAvailable is returend when given hash function is not available but reqested.
var ErrHashNotAvailable = errors.New(
	"uciph: hash.Hash availability check filed. Check out hash.Hash.Available() from golang STL for more info" +
		"Note: Try import _ \"*YOUR HASH PACKAGE LIKE crypto/sha256*\"",
)

// ErrSignInvalid is returned by verifier when sign it's given is invalid.
var ErrSignInvalid = errors.New("uciph: Given sign is invalid! Sign verification filed")

// ErrTooManyChunksEncrypted is returned when nonce counter is about to overflow.
// Usually it's returned to prevent xoring with same keystream again and prevent panicking.
var ErrTooManyChunksEncrypted = errors.New("uciph: This encryptor can't safely encrypt more chunks")

// ErrInvalidKeySize is returned when key has invalid size
var ErrInvalidKeySize = errors.New("uciph: Given key has invalid size")

// ErrInvalidOverlap is retuned when append to overlaping rule is broken.
var ErrInvalidOverlap = errors.New("uciph: Slices are not overlapping each other correctly")

// ErrStreamLogicEnd is returned when StreamDecryptor finds out that stream contains more data than it should.
var ErrStreamLogicEnd = errors.New("uciph: Given stream has endend logically but more data is supplied to StreamDecryptor")

// ErrStreamChunksReordered is returned when StreamDecryptor finds out that stream has reordered chunks
// and thus data has been tampered with.
var ErrStreamChunksReordered = errors.New("uciph: Chunks of this encrypted stream have been reordered")

// ErrStreamTruncated is returned when stream logically has more data but it hasn't arrived.
var ErrStreamTruncated = errors.New("uciph: This stream logically should have more data")

// ErrChunkTooBig is returend when chunk is too big
var ErrChunkTooBig = errors.New("uciph: This stream contains too long chunks and can't be processed")

// ErrPowInvalid is returned when POW solution is not valid.
var ErrPowInvalid = errors.New("uciph: POW filed. This solution is not valid")
