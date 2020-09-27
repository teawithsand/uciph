package pwhash

import (
	"fmt"

	"github.com/teawithsand/uciph/rand"
)

// HashVersion is hasher identifier used for hash versioning.
type HashVersion = uint64

// HashVersionMismatchError is returned when PWHash version does not match one in hash.
type HashVersionMismatchError struct {
	CurrentVersion HashVersion
	GivenVersion   HashVersion
}

func (e *HashVersionMismatchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("uciph/cutil/pwhash: HashVersionMistmatchError: got: %d expected %d", e.GivenVersion, e.CurrentVersion)
}

// Hasher is function-based hasher, which is able to hash passwords.
type Hasher = func(password []byte) (hash PWHash, err error)

// Verifier verifies hashes produced by PasswordHasher.
type Verifier = func(password []byte, hash PWHash) (equal bool, err error)

type Options struct {
	HashVersion HashVersion

	SaltSize int
	SaltRNG  rand.RNG

	// Like salt, but stored outside DB and same for all users.
	// It's prepended to each password.
	// It should be long enough not to be brute-forceable.
	Pepper []byte
}

// Argon2Options represents Argon2 specific options.
type Argon2Options struct {
	Memory  uint32
	Threads uint8
	Time    uint32
	KeyLen  uint32
}
