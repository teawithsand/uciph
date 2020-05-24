package uciph_test

import (
	"testing"

	"github.com/teawithsand/uciph"
)

// TODO(teawithsand): benchmark signing

func TestEd25519_DefaultConfig(t *testing.T) {
	DoTestSignerVerifier(
		func() (uciph.Signer, uciph.Verifier) {
			rvk, rsk, err := uciph.Ed25519Keygen.GenSigKey(nil)
			if err != nil {
				panic(err)
			}
			vk, err := uciph.Ed25519KeyParser.ParseVerKey(rvk)
			if err != nil {
				panic(err)
			}
			sk, err := uciph.Ed25519KeyParser.ParseSigKey(rsk)
			if err != nil {
				panic(err)
			}
			ver, err := vk.NewVerifier(nil)
			if err != nil {
				panic(err)
			}
			sig, err := sk.NewSigner(nil)
			if err != nil {
				panic(err)
			}
			return sig, ver
		},
		true,
		t,
	)
}

type sopt struct{}

func (sopt) SigningHasher() uciph.Hasher {
	return nil
}

func TestEd25519_NoHasherButBuffering(t *testing.T) {
	DoTestSignerVerifier(
		func() (uciph.Signer, uciph.Verifier) {
			rvk, rsk, err := uciph.Ed25519Keygen.GenSigKey(nil)
			if err != nil {
				panic(err)
			}
			vk, err := uciph.Ed25519KeyParser.ParseVerKey(rvk)
			if err != nil {
				panic(err)
			}
			sk, err := uciph.Ed25519KeyParser.ParseSigKey(rsk)
			if err != nil {
				panic(err)
			}
			ver, err := vk.NewVerifier(sopt{})
			if err != nil {
				panic(err)
			}
			sig, err := sk.NewSigner(sopt{})
			if err != nil {
				panic(err)
			}
			return sig, ver
		},
		false,
		t,
	)
}
