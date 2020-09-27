package pwhash

import (
	"crypto/hmac"
	"io"

	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/argon2"
)

// Argon2ID creates Argon2 hasher and verifier for givne options
func Argon2ID(commonOptions Options, a2options Argon2Options) (h Hasher, v Verifier) {
	if a2options.Memory == 0 {
		a2options.Memory = 32 * 1024
	}
	if a2options.Time == 0 {
		a2options.Time = 1
	}
	if a2options.Threads == 0 {
		a2options.Threads = 1
	}
	if a2options.KeyLen == 0 {
		a2options.KeyLen = 32
	}
	if commonOptions.SaltRNG == nil {
		commonOptions.SaltRNG = rand.DefaultRNG()
	}
	h = Hasher(func(password []byte) (hash PWHash, err error) {
		var salt []byte
		if commonOptions.SaltSize != 0 {
			salt = make([]byte, commonOptions.SaltSize)
			_, err = io.ReadFull(commonOptions.SaltRNG, salt[:])
			if err != nil {
				return
			}
		}

		var passwordBuffer []byte
		if len(commonOptions.Pepper) > 0 {
			// pepper + password
			passwordBuffer = make([]byte, len(commonOptions.Pepper)+len(password))
			copy(passwordBuffer[:len(commonOptions.Pepper)], commonOptions.Pepper)
			copy(passwordBuffer[len(commonOptions.Pepper):], password)
		} else {
			passwordBuffer = password
		}

		rawHash := argon2.IDKey(passwordBuffer, salt, a2options.Time, a2options.Memory, a2options.Threads, a2options.KeyLen)

		hash = PWHash{
			Version: commonOptions.HashVersion,
			Hash:    rawHash,
			Salt:    salt,
		}
		return
	})

	v = Verifier(func(password []byte, hash PWHash) (equal bool, err error) {
		if hash.Version != commonOptions.HashVersion {
			err = &HashVersionMismatchError{
				CurrentVersion: commonOptions.HashVersion,
				GivenVersion:   hash.Version,
			}
			return
		}
		if uint64(len(hash.Hash)) != uint64(a2options.KeyLen) {
			equal = false
			return
		}

		var passwordBuffer []byte
		if len(commonOptions.Pepper) > 0 {
			// pepper + password
			passwordBuffer = make([]byte, len(commonOptions.Pepper)+len(password))
			copy(passwordBuffer[:len(commonOptions.Pepper)], commonOptions.Pepper)
			copy(passwordBuffer[len(commonOptions.Pepper):], password)
		} else {
			passwordBuffer = password
		}

		rawHash := argon2.IDKey(passwordBuffer, hash.Salt, a2options.Time, a2options.Memory, a2options.Threads, a2options.KeyLen)

		equal = hmac.Equal(rawHash, hash.Hash)
		return
	})

	return
}
