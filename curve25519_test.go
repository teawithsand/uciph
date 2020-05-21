package uciph_test

import (
	"bytes"
	"testing"

	"github.com/teawithsand/uciph"
)

func TestCurve25519KX_WorksAsExpected(t *testing.T) {
	for i := 0; i < 10; i++ { // RNG is in use
		var err error
		noErr := func() {
			if err != nil {
				t.Error(err)
			}
		}
		pk1, sk1, err := uciph.Curve25519KXGen.GenKX(nil)
		noErr()
		pk2, sk2, err := uciph.Curve25519KXGen.GenKX(nil)
		noErr()
		ppk1, err := uciph.Curve25519KXParser.ParsePubKX(pk1)
		noErr()
		ppk2, err := uciph.Curve25519KXParser.ParsePubKX(pk2)
		noErr()

		psk1, err := uciph.Curve25519KXParser.ParseSecKX(sk1)
		noErr()
		psk2, err := uciph.Curve25519KXParser.ParseSecKX(sk2)
		noErr()

		res1, err := psk1.MixWithPub(ppk2, nil, nil)
		noErr()

		res2, err := psk2.MixWithPub(ppk1, nil, nil)
		noErr()

		if bytes.Compare(res1, res2) != 0 {
			t.Error("Keys are not equal!")
		}
	}
}

func TestCurve25519KX_DoesNotGiveSameResult_WhenDataModified(t *testing.T) {
	for i := 0; i < 10; i++ { // RNG is in use
		var err error
		noErr := func() {
			if err != nil {
				t.Error(err)
			}
		}
		pk1, sk1, err := uciph.Curve25519KXGen.GenKX(nil)
		noErr()
		pk2, sk2, err := uciph.Curve25519KXGen.GenKX(nil)
		noErr()
		pk3, sk3, err := uciph.Curve25519KXGen.GenKX(nil)
		noErr()

		ppk1, err := uciph.Curve25519KXParser.ParsePubKX(pk1)
		noErr()
		ppk2, err := uciph.Curve25519KXParser.ParsePubKX(pk2)
		noErr()
		ppk3, err := uciph.Curve25519KXParser.ParsePubKX(pk3)
		noErr()

		psk1, err := uciph.Curve25519KXParser.ParseSecKX(sk1)
		noErr()
		psk2, err := uciph.Curve25519KXParser.ParseSecKX(sk2)
		noErr()
		psk3, err := uciph.Curve25519KXParser.ParseSecKX(sk3)
		noErr()

		res1, err := psk1.MixWithPub(ppk2, nil, nil)
		noErr()

		res2, err := psk2.MixWithPub(ppk3, nil, nil)
		noErr()

		_ = psk1
		_ = ppk1
		_ = psk3

		if bytes.Compare(res1, res2) == 0 {
			t.Error("Keys are equal!")
		}
	}
}
