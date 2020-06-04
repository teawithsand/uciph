package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/enc"
)

func TestAESEncryptAndDecrypt(t *testing.T) {
	doTest := func(t *testing.T, size int) {
		var encOpts interface{} = nmopts{
			nm: enc.NonceModeRandom,
		}
		var decOpts interface{} = nmopts{
			nm: enc.NonceModeRandom,
		}
		fac := func() (enc.Encryptor, enc.Decryptor) {
			kg, err := enc.AESGCMKeyGen(size)
			if err != nil {
				t.Error(err)
			}
			rawKey, err := kg.GenSymmKey(nil, nil)
			if err != nil {
				t.Error(err)
			}
			kp, err := enc.AESGCMKeyParser(size)
			if err != nil {
				t.Error(err)
			}
			ek, err := kp.ParseEncKey(rawKey)
			if err != nil {
				t.Error(err)
			}
			dk, err := kp.ParseDecKey(rawKey)
			if err != nil {
				t.Error(err)
			}
			enc, err := ek.NewEncryptor(encOpts)
			if err != nil {
				t.Error(err)
			}
			dec, err := dk.NewDecryptor(decOpts)
			if err != nil {
				t.Error(err)
			}
			return enc, dec
		}
		DoTestEncryptorDecryptor(t.Error, fac, testData{IsAEAD: true})

		// swap nonce mode and run again
		encOpts = nmopts{
			nm: enc.NonceModeCounter,
		}
		decOpts = nmopts{
			nm: enc.NonceModeCounter,
		}
		DoTestEncryptorDecryptor(t.Error, fac, testData{IsAEAD: true})
	}
	doTest(t, 128/8)
	doTest(t, 192/8)
	doTest(t, 256/8)
}
