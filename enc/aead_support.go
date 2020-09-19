package enc

import (
	"crypto/cipher"
	"io"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/cutil"
	"github.com/teawithsand/uciph/enc/internal"
	"github.com/teawithsand/uciph/rand"
)

// TODO(teawithsand): integrate good overlapping checks here
// since these do not work.

// NewCtrAEADEncryptor wraps any AEAD and uses it to encrypt chunks.
// It uses nonce coutner to manage nonces.
func NewCtrAEADEncryptor(aead cipher.AEAD, options interface{}) Encryptor {
	var nc cutil.NonceCounter

	// TODO(teawihtsand): allow NonceCounter from options
	if nc == nil {
		nc = cutil.NonceCounterForAEAD(aead)
	}
	if aead.NonceSize() != nc.Len() {
		panic("uciph/enc: Nonce length mismatch between cipher.AEAD and NonceCounter")
	}
	return EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		if internal.AnyOverlap(in, appendTo) && internal.InexactOverlap(in, appendTo) {
			appendTo = nil // make it work always, sometimes not in place(?)
		}

		defer func() {
			err = nc.Increment()
		}()
		res = aead.Seal(appendTo, nc[:], in, nil)
		return
	})
}

// NewCtrAEADDecryptor wraps any AEAD and uses it to decrypt chunks.
// It uses nonce coutner to manage nonces.
func NewCtrAEADDecryptor(aead cipher.AEAD, options interface{}) Decryptor {
	var nc cutil.NonceCounter

	// TODO(teawihtsand): allow NonceCounter from options
	if nc == nil {
		nc = cutil.NonceCounterForAEAD(aead)
	}
	if aead.NonceSize() != nc.Len() {
		panic("uciph/enc: Nonce length mismatch between cipher.AEAD and NonceCounter") // err here?
	}
	return DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		if internal.InexactOverlap(in, appendTo) {
			appendTo = nil // make it work always, sometimes not in place(?)
		}

		defer func() {
			if err == nil {
				// increment only if succeed? Anyhow decryptor should not be reused after failure.
				err = nc.Increment()
			}
		}()
		res, err = aead.Open(appendTo, nc[:], in, nil)
		return
	})
}

// NewRNGAEADEncryptor creates new encryptor, which uses RNG from options to generate
// nonces.
// Note: It has no limit dependent on nonce length, which may be unsafe sometimes.
// For instance 12 byte random nonce should not be used more than 2**32 times!
func NewRNGAEADEncryptor(aead cipher.AEAD, options interface{}) Encryptor {
	nc := make([]byte, aead.NonceSize())
	rng := rand.GetRNG(options)

	return EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		_, err = io.ReadFull(rng, nc[:])
		if err != nil {
			return
		}

		if internal.InexactOverlap(in, appendTo) {
			appendTo = nil // make it work always, sometimes not in place(?)
		}

		// This one was prepending version
		/*
			appendTo = append(appendTo, nc[:]...)
			res = aead.Seal(appendTo, nc[:], in, nil)
			copy(appendTo, nc[:])
		*/

		// note: nonce size is assumed to be known
		// so there is no need to write it
		res = aead.Seal(appendTo, nc[:], in, nil)
		res = append(res, nc[:]...)
		return
	})
}

// NewRNGAEADDecryptor creates new decryptor, which is able to decrypt data encrypted using NewRngAEADEncryptor.
func NewRNGAEADDecryptor(aead cipher.AEAD, options interface{}) Decryptor {
	nsz := aead.NonceSize()

	// This one was prepending version
	/*
		// does this make any sense?
		// in C it does...
		var lnb [24]byte
		var nonceBuffer []byte
		if nsz > len(lnb) {
			nonceBuffer = make([]byte, nsz)
		} else {
			nonceBuffer = lnb[:nsz]
		}
		_ = nonceBuffer
	*/
	return DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		if len(in) < nsz {
			err = uciph.ErrNonceInvalid
			return
		}
		nonce := in[len(in)-nsz:]
		in = in[:len(in)-nsz]
		res, err = aead.Open(appendTo, nonce, in, nil)

		// This one was prepending version
		/*
			if len(in) < nsz {
				err = uciph.ErrNonceInvalid
				return
			}

			if internal.InexactOverlap(in, appendTo) {
				appendTo = nil // make it work always, sometimes not in place(?)
			}

			// TODO(teawihtsand): consider appending nonce to the end, since this makes overlapping slice
			// handling much easier
			// TODO(teawithsand): eliminate copy to nonceBuffer if slices do not overlap for more cases
			// TODO(teawithsand): check if this hack really works when slies do and do not overlap
			// TODO(teawithsand): make it not leave garbage nonce bytes at the beggining, which are not part of res
			// for most cases it's fine but it leaks something between 12 and 24 bytes of memory
			//
			// it works like so:
			// [1, 2, 3, 4, 5, 6, 7, 8] <- in buffer
			// then in is curred to [3, 4, 5, 6]
			// then two bytes are nonce and two are data(in this case)
			// so in now looks like (DBX are decrypted bytes)
			// [1, 2, 0, 0, DB1, DB2, 7, 8]
			// And res pointss to [DB1, DB2]
			// Is it fine to leave modified bytes in in, which are not part of res?
			// In fact we could revert them(although it's not easy and requires some hacking since we have to make sure that in == appendTo), but is that required?
			// Right now I am going to leave it as-is.

			if appendTo == nil {
				res, err = aead.Open(nil, in[:nsz], in[nsz:], nil)
			} else {
				// 1. Copy nonce to buffer
				copy(nonceBuffer, in[:nsz])

				for i := 0; i < nsz; i++ {
					appendTo = append(appendTo, 0)
				}
				res, err = aead.Open(appendTo[nsz:], nonceBuffer, in[nsz:], nil)
			}
		*/
		return
	})
}
