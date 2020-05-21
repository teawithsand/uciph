package uciph_test

import (
	"testing"

	"github.com/teawithsand/uciph"
)

func TestBlankEncryptor(t *testing.T) {
	DoTestEncryptorDecryptor(func() (uciph.Encryptor, uciph.Decryptor) {
		return uciph.BlankEncryptor, uciph.BlankDecryptor
	}, t)
}
