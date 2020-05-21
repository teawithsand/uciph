package uciph

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

var Curve25519KXGen KXGen = KXGenFunc(func(options KXGenOptions) (pub, sec []byte, err error) {
	rng := GetRNG(options)
	var sk [curve25519.ScalarSize]byte
	_, err = io.ReadFull(rng, sk[:])
	if err != nil {
		return
	}

	sec = sk[:]
	var pk [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	pub = make([]byte, len(pk))
	copy(pub[:], pk[:])

	sec = make([]byte, len(sk))
	copy(sec[:], sk[:])

	return
})

type curve25519Parser struct{}

func (curve25519Parser) ParsePubKX(data []byte) (PubKX, error) {
	var pk curve25519PubKey
	if len(data) != len(pk) {
		return nil, ErrKeyInvalid
	}
	copy(pk[:], data)
	return pk, nil
}

func (curve25519Parser) ParseSecKX(data []byte) (SecKX, error) {
	var sk curve25519SecKey
	if len(data) != len(sk) {
		return nil, ErrKeyInvalid
	}
	copy(sk[:], data)
	return sk, nil
}

// Curve25519KXParser parses curve25519 key exchange.
var Curve25519KXParser KXParser = curve25519Parser{}

type curve25519PubKey [curve25519.PointSize]byte
type curve25519SecKey [curve25519.ScalarSize]byte

func (sk curve25519SecKey) MixWithPub(pubKX PubKX, options MixWithPubOptions, appendTo []byte) (data []byte, err error) {
	cpk, ok := pubKX.(curve25519PubKey)
	if !ok {
		return nil, ErrKeyTypeInvalid
	}

	npk := [32]byte(cpk)
	nsk := [32]byte(sk)

	var dst [32]byte
	curve25519.ScalarMult(&dst, &nsk, &npk)
	data = append(appendTo, dst[:]...)

	return
}
