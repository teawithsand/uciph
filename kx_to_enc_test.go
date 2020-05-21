package uciph_test

import (
	"testing"

	"github.com/teawithsand/uciph"
)

func TestKXToEncEncryptAndDecrypt(t *testing.T) {
	DoTestEncryptorDecryptor(
		func() (uciph.Encryptor, uciph.Decryptor) {
			var err error
			noErr := func() {
				if err != nil {
					t.Error(err)
					panic(err)
				}
			}
			rawPub, rawSec, err := uciph.Curve25519KXGen.GenKX(nil)
			noErr()
			pubKX, err := uciph.Curve25519KXParser.ParsePubKX(rawPub)
			noErr()
			secKX, err := uciph.Curve25519KXParser.ParseSecKX(rawSec)
			noErr()
			encK, err := uciph.NewKXParsedEncKey(
				uciph.Curve25519KXGen,
				pubKX,
				uciph.Curve25519KXParser,
				func(kxResult []byte) (uciph.Encryptor, error) {
					// use blank encryptor
					return uciph.BlankEncryptor, nil
				},
			)
			noErr()
			decK, err := uciph.NewKXParsedDecKey(
				uciph.Curve25519KXGen,
				secKX,
				uciph.Curve25519KXParser,
				func(kxResult []byte) (uciph.Decryptor, error) {
					return uciph.BlankDecryptor, nil
				},
			)
			noErr()

			enc, err := encK.NewEncryptor(nil)
			noErr()

			dec, err := decK.NewDecryptor(nil)
			noErr()

			return enc, dec
		},
		t,
	)
}

// note: there is no failure test, since it requires real encryptor
// TODO(teawithsand): write one test, which uses real AEAD encryptor and fails on invalid key
