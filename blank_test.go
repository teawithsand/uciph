package uciph_test

import (
	"testing"

	"github.com/teawithsand/uciph"
)

func TestBlankEncryptorDecryptor(t *testing.T) {
	DoTestEncryptorDecryptor(func() (uciph.Encryptor, uciph.Decryptor) {
		return uciph.BlankEncryptor, uciph.BlankDecryptor
	}, t)
}

func BenchmarkBlankEncryptor(b *testing.B) {
	benchmarkEncryptor(b, func() uciph.Encryptor {
		return uciph.BlankEncryptor
	})
}
