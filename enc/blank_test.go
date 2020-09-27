package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/ctest"
	"github.com/teawithsand/uciph/enc"
)

func TestBlankED(t *testing.T) {
	ctest.DoTestED(t, func() (enc.Encryptor, enc.Decryptor) {
		return enc.BlankEncryptor(), enc.BlankDecryptor()
	}, ctest.TestEDConfig{
		IsAEAD: false,
	})
}

func BenchmarkBlankED(b *testing.B) {
	cbe := cbench.EDBenchEngine{
		Fac: func() (enc.Encryptor, enc.Decryptor) {
			return enc.BlankEncryptor(), enc.BlankDecryptor()
		},
		Config: cbench.EDBenchConfig{
			Runs: cbench.GenereateDefaultEDRuns(false),
		},
	}
	cbe.RunEDBenchmark(b)
}
