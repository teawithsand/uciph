package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/enc"
)

func TestBlankEncryptorDecryptor(t *testing.T) {
	DoTestEncryptorDecryptor(t.Error, func() (enc.Encryptor, enc.Decryptor) {
		return enc.BlankEncryptor(), enc.BlankDecryptor()
	}, testData{IsAEAD: false})
}

/*

func BenchmarkBlankEncryptor(b *testing.B) {
	benchmarkEncryptor(b, func() uciph.Encryptor {
		return uciph.BlankEncryptor
	})
}

*/
