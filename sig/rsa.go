package sig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/rand"
)

type rsaParser struct {
	Size int
}

// ParseSigKey parses signing key.
func (p rsaParser) ParseSigKey(data []byte) (SigKey, error) {
	secKey, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	if secKey.Size() != p.Size {
		return nil, uciph.ErrInvalidKeySize
	}
	// Should primes be rabin-miller checked here?
	// Or should it be fully predictable

	// check if key is valid and primes are prmes
	err = secKey.Validate()
	if err != nil {
		return nil, err
	}
	return rsaSigKey(*secKey), nil
}

// ParseVerKey parses verifying key.
func (p rsaParser) ParseVerKey(data []byte) (VerKey, error) {
	pubKey, err := x509.ParsePKCS1PublicKey(data)
	if err != nil {
		return nil, err
	}
	if pubKey.Size() != p.Size {
		return nil, uciph.ErrInvalidKeySize
	}
	return rsaVerKey(*pubKey), nil
}

// RSAKeyParser creates parser for RSA keys with specified size.
// It returns nil if size is not supported.
func RSAKeyParser(size int) SigVerKeyParser {
	if size != 1024 && size != 1024*2 && size != 1024*4 {
		return nil
	}
	return &rsaParser{
		Size: size,
	}
}

// RSAKeygen creates RSA key generator for specified key size.
// Note: despite the fact that RSA 1024 is allowed it should be used no more.
// It's deprecated and attacker with enough funds(like goverment) is likely to be able to break it.
func RSAKeygen(size int) (SigKeygen, error) {
	if size != 1024 && size != 1024*2 && size != 1024*4 {
		return nil, uciph.ErrInvalidKeySize
	}

	return SigKeygenFunc(func(options interface{}, vkAppendTo, skAppendTo []byte) (vk, sk []byte, err error) {
		secKey, err := rsa.GenerateKey(rand.GetRNG(options), size)
		if err != nil {
			return
		}
		vkAppendTo = append(vkAppendTo, x509.MarshalPKCS1PublicKey(&secKey.PublicKey)...)
		skAppendTo = append(skAppendTo, x509.MarshalPKCS1PrivateKey(secKey)...)
		vk = vkAppendTo
		sk = skAppendTo
		return
	}), nil
}

type rsaSigKey rsa.PrivateKey

type rsaVerKey rsa.PublicKey

// NewSigner creates signer for given RSA secret key.
func (k rsaSigKey) NewSigner(options interface{}) (Signer, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}

	privK := rsa.PrivateKey(k)
	rng := rand.GetRNG(options)

	doSign := func(data, appendTo []byte) (res []byte, err error) {
		// var h crypto.Hash
		// TODO(teawithsand): auto determine hash here rather than forcing unknown hash
		/*
			if len(data) == 256/8 {
				h = crypto.SHA256
			} else if len(data) == 384/8 {
				h = crypto.SHA384
			} else if len(data) == 512/8 {
				h = crypto.SHA512
			} else {
				panic("TODO REPORT ERROR INVALID DATA LENGTH")
			}
		*/

		sign, err := rsa.SignPKCS1v15(rng, &privK, 0, data)
		if err != nil {
			return
		}
		res = append(appendTo, sign...)
		return
	}

	if hasher != nil {
		return &hashSigner{
			hasher: hasher,
			doSign: doSign,
		}, nil
	}

	return &bufferSigner{
		buf:    bytes.NewBuffer(nil),
		doSign: doSign,
	}, nil
}

// NewVerifier creates verifeir for given RSA key.
func (k rsaVerKey) NewVerifier(options interface{}) (Verifier, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}

	verK := rsa.PublicKey(k)
	doVerify := func(data, sign []byte) error {
		// TODO(teawithsand): auto determine hash here rather than forcing unknown hash

		var h crypto.Hash
		/*
			if len(data) == 256/8 {
				h = crypto.SHA256
			} else if len(data) == 384/8 {
				h = crypto.SHA384
			} else if len(data) == 512/8 {
				h = crypto.SHA512
			} else {
				panic("TODO REPORT ERROR INVALID DATA LENGTH")
			}
		*/

		err = rsa.VerifyPKCS1v15(&verK, h, data, sign)
		if errors.Is(err, rsa.ErrVerification) {
			err = uciph.ErrSignInvalid
		}
		return nil
	}

	if hasher != nil {
		return &hashVerifier{
			hasher:   hasher,
			doVerify: doVerify,
		}, nil
	}

	return &bufferVerifier{
		buf:      bytes.NewBuffer(nil),
		doVerify: doVerify,
	}, nil
}

/*
// ParseSigKey parses signing key.
func (ed25519parser) ParseSigKey(data []byte) (SigKey, error) {
	var sk ed25519SigKey
	if len(sk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(sk[:], data)
	return sk, nil
}

// ParseVerKey parses verifying key.
func (ed25519parser) ParseVerKey(data []byte) (VerKey, error) {
	var vk ed25519VerKey
	if len(vk) != len(data) {
		return nil, uciph.ErrKeyInvalid
	}
	copy(vk[:], data)
	return vk, nil
}

func (k ed25519SigKey) NewSigner(options interface{}) (Signer, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}
	doSign := func(data, appendTo []byte) (res []byte, err error) {
		sign := ed25519.Sign(ed25519.PrivateKey(k[:]), data)
		res = append(appendTo, sign...)
		return
	}
	if hasher != nil {
		return &hashSigner{
			hasher: hasher,
			doSign: doSign,
		}, nil
	} else {
		return &bufferSigner{
			buf:    bytes.NewBuffer(nil),
			doSign: doSign,
		}, nil
	}
}

func (k ed25519VerKey) NewVerifier(options interface{}) (Verifier, error) {
	hasher, err := GetSigningHasher(options)
	if err != nil {
		return nil, err
	}
	doVerify := func(data, sign []byte) error {
		if !ed25519.Verify(ed25519.PublicKey(k[:]), data, sign) {
			return uciph.ErrSignInvalid
		}
		return nil
	}
	if hasher != nil {
		return &hashVerifier{
			hasher:   hasher,
			doVerify: doVerify,
		}, nil
	} else {
		return &bufferVerifier{
			buf:      bytes.NewBuffer(nil),
			doVerify: doVerify,
		}, nil
	}
}

*/
