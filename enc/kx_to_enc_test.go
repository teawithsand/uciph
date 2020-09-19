package enc_test

import (
	"testing"

	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/kx"
)

func TestKXToEnc(t *testing.T) {
	t.Run("Curve25519_With_ChaCha20", func(t *testing.T) {
		DoTestED(t, func() (enc.Encryptor, enc.Decryptor) {
			g := &kx.Generated{}
			err := kx.GenCurve25519(nil, g)
			if err != nil {
				panic(err)
			}

			ek, err := enc.NewKXEncKey(kx.GenCurve25519, kx.Curve25519, g.PublicPart, func(options interface{}, kxResult []byte) (e enc.Encryptor, err error) {
				// fmt.Println("Enc key:", kxResult)

				ek, err := enc.ParseChaCha20Poly1305EncKey(kxResult)
				if err != nil {
					return
				}
				// do not use non-counter nonce for these
				// as encryption keys are unique anyway
				options = &nmopts{
					nm: enc.NonceModeCounter,
				}
				origE, err := ek(options)
				if err != nil {
					return
				}

				e = enc.EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
					// fmt.Println("Encrypted: ", in)
					res, err = origE.Encrypt(in, appendTo)
					// fmt.Println("Got: ", res, err)
					return
				})

				return
			})
			if err != nil {
				panic(err)
			}

			dk, err := enc.NewKXDecKey(kx.Curve25519, g.SecretPart, func(options interface{}, kxResult []byte) (d enc.Decryptor, err error) {
				// fmt.Println("Dec key:", kxResult)

				dk, err := enc.ParseChaCha20Poly1305DecKey(kxResult)
				if err != nil {
					return
				}
				// do not use non-counter nonce for these
				// as encryption keys are unique anyway
				options = &nmopts{
					nm: enc.NonceModeCounter,
				}
				origD, err := dk(options)
				if err != nil {
					return
				}

				d = enc.DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
					// fmt.Println("Decrypting: ", in)
					res, err = origD.Decrypt(in, appendTo)
					// fmt.Println("Got: ", res, err)
					return
				})

				return
			})
			if err != nil {
				panic(err)
			}

			encryptor, err := ek(nil)
			if err != nil {
				panic(err)
			}

			decryptor, err := dk(nil)
			if err != nil {
				panic(err)
			}

			return encryptor, decryptor
		}, TestEDConfig{
			IsAEAD: true,
		})
	})
}
