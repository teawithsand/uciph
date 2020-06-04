package kx

import (
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
	"golang.org/x/crypto/curve25519"
)

var curve25519KXGen = GenFunc(func(options interface{}, pubAppendTo, secAppendTo []byte) (pub, sec []byte, err error) {
	rng := rand.GetRNG(options)
	var sk [curve25519.ScalarSize]byte
	_, err = io.ReadFull(rng, sk[:])
	if err != nil {
		return
	}

	sec = sk[:]
	var pk [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	pub = append(pubAppendTo, pub[:]...)
	// make([]byte, len(pk))
	// copy(pub[:], pk[:])

	// sec = make([]byte, len(sk))
	// copy(sec[:], sk[:])
	sec = append(secAppendTo, sec[:]...)

	return
})

// Curve25519Gen generates curve25519 key exchange keys.
func Curve25519Gen() Gen {
	return curve25519KXGen
}

type curve25519Parser struct{}

func (curve25519Parser) ParsePubKX(data []byte) (Pub, error) {
	var pk curve25519PubKey
	if len(data) != len(pk) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(pk[:], data)
	return pk, nil
}

func (curve25519Parser) ParseSecKX(data []byte) (Sec, error) {
	var sk curve25519SecKey
	if len(data) != len(sk) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(sk[:], data)
	return sk, nil
}

var curve25519KXParser = curve25519Parser{}

// Curve25519Parser parses curve25519 key exchange, both public and secret part.
func Curve25519Parser() Parser {
	return curve25519KXParser
}

type curve25519PubKey [curve25519.PointSize]byte
type curve25519SecKey [curve25519.ScalarSize]byte

func (sk curve25519SecKey) MixWithPub(pubKX Pub, options interface{}, appendTo []byte) (data []byte, err error) {
	cpk, ok := pubKX.(curve25519PubKey)
	if !ok {
		return nil, uciph.ErrKeyTypeInvalid
	}

	npk := [32]byte(cpk)
	nsk := [32]byte(sk)

	var dst [32]byte
	curve25519.ScalarMult(&dst, &nsk, &npk)
	data = append(appendTo, dst[:]...)

	return
}
