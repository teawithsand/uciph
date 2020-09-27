package pwhash

import (
	"errors"
	"fmt"
)

// NoVerifierMatchedError is returned, when no verifier could be matched in given VerifierChain.
type NoVerifierMatchedError struct {
	Version HashVersion
}

func (e *NoVerifierMatchedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("uciph/cutil/pwhash: No verifier found for version: %d", e.Version)
}

// VerifierChain creates verifier, which ingores HashVersionMismatchError and
// goes to next vefifier if such error occurrs.
//
// Used for password versioning.
func VerifierChain(
	verifiers ...Verifier,
) Verifier {
	return Verifier(func(password []byte, hash PWHash) (equal bool, err error) {
		for _, v := range verifiers {
			equal, err = v(password, hash)
			var hve *HashVersionMismatchError
			if errors.As(err, &hve) {
				equal = false
				err = nil
				continue
			} /* else if err != nil {
				return
			} else */{
				return
			}
		}
		err = &NoVerifierMatchedError{
			Version: hash.Version,
		}
		return
	})
}
