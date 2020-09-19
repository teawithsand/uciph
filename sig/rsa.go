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

// RSAKeySize denotes RSA key size(in bits), which is accepted by this library.
type RSAKeySize int

const (
	RSA1024 RSAKeySize = 1024
	RSA2048 RSAKeySize = 2048
	RSA4096 RSAKeySize = 4096
)

// Check checks if RSA key is valid or not.
func (s RSAKeySize) Check() (err error) {
	size := int(s)
	if size != 1024 && size != 1024*2 && size != 1024*4 {
		return uciph.ErrInvalidKeySize
	}

	return
}

// NewRSAKeygen creates RSA keygen for specified key size.
func NewRSAKeygen(size RSAKeySize) (Keygen, error) {
	err := size.Check()
	if err != nil {
		return nil, err
	}

	return func(options interface{}, gk *GeneratedKeys) (err error) {
		secKey, err := rsa.GenerateKey(rand.GetRNG(options), int(size))
		if err != nil {
			return
		}
		gk.VerifyingKey = append(gk.VerifyingKey, x509.MarshalPKCS1PublicKey(&secKey.PublicKey)...)
		gk.SigningKey = append(gk.SigningKey, x509.MarshalPKCS1PrivateKey(secKey)...)
		return
	}, nil
}

// RSAKeygen generates RSA key with specified size.
func RSAKeygen(options interface{}, size RSAKeySize, dst *GeneratedKeys) error {
	kg, err := NewRSAKeygen(size)
	if err != nil {
		return err
	}
	return kg(options, dst)
}

// NewRSASigKeyParser creates RSA signing key parser for specified key size.
func NewRSASigKeyParser(size RSAKeySize) (SigKeyParser, error) {
	err := size.Check()
	if err != nil {
		return nil, err
	}

	return func(data []byte) (SigKey, error) {
		secKey, err := x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			return nil, err
		}
		if secKey.Size() != int(size) {
			return nil, uciph.ErrInvalidKeySize
		}
		// Should primes be rabin-miller checked here?
		// Or should it be fully predictable

		// check if key is valid and primes are prmes
		err = secKey.Validate()
		if err != nil {
			return nil, err
		}

		return func(options interface{}) (Signer, error) {
			hasher, err := GetSigningHasher(options)
			if err != nil {
				return nil, err
			}

			privK := rsa.PrivateKey(*secKey)
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
		}, nil
	}, nil
}

// NewRSAVerKeyParser creates RSA verifying key parser for specified key size.
func NewRSAVerKeyParser(size RSAKeySize) (VerKeyParser, error) {
	err := size.Check()
	if err != nil {
		return nil, err
	}

	return func(data []byte) (VerKey, error) {
		pubKey, err := x509.ParsePKCS1PublicKey(data)
		if err != nil {
			return nil, err
		}
		if pubKey.Size() != int(size) {
			return nil, uciph.ErrInvalidKeySize
		}
		// Should primes be rabin-miller checked here?
		// Or should it be fully predictable

		// check if key is valid and primes are prmes
		/*
			err = pubKey.Validate()
			if err != nil {
				return nil, err
			}
		*/

		return func(options interface{}) (Verifier, error) {
			hasher, err := GetSigningHasher(options)
			if err != nil {
				return nil, err
			}

			verK := rsa.PublicKey(*pubKey)
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
		}, nil
	}, nil
}

// ParseRSAVerKey parses RSA verifying key with specified size.
func ParseRSAVerKey(data []byte, size RSAKeySize) (VerKey, error) {
	vkp, err := NewRSAVerKeyParser(size)
	if err != nil {
		return nil, err
	}
	return vkp(data)
}

// ParseRSASigKey parses RSA signing key with specified size.
func ParseRSASigKey(data []byte, size RSAKeySize) (SigKey, error) {
	skp, err := NewRSASigKeyParser(size)
	if err != nil {
		return nil, err
	}
	return skp(data)
}
