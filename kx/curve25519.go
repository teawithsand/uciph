package kx

import (
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/curve25519"
)

// GenCurve25519 creates KX pair.
func GenCurve25519(options interface{}, res *Generated) (err error) {
	if res == nil {
		panic("uciph/kx: nil *Generated provided to GenCurve25519")
	}
	rng := rand.GetRNG(options)
	var sk [curve25519.ScalarSize]byte
	_, err = io.ReadFull(rng, sk[:])
	if err != nil {
		return
	}

	var pk [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	res.SecretPart = append(res.SecretPart, sk[:]...)
	res.PublicPart = append(res.PublicPart, pk[:]...)

	return
}

// Curve25519 performs curve25519 key exchange on parts it's given.
func Curve25519(options interface{}, public, secret, res []byte) (dst []byte, err error) {
	if len(public) != curve25519.PointSize {
		err = uciph.ErrKeyInvalid
		return
	}
	if len(secret) != curve25519.ScalarSize {
		err = uciph.ErrKeyInvalid
		return
	}

	var pubPart [curve25519.PointSize]byte
	var secPart [curve25519.ScalarSize]byte
	copy(pubPart[:], public)
	copy(secPart[:], secret)

	var destPart [32]byte

	curve25519.ScalarMult(&destPart, &secPart, &pubPart)

	dst = append(res, destPart[:]...)
	return
}
