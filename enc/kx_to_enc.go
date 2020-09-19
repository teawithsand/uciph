package enc

import (
	"encoding/binary"

	"github.com/teawithsand/uciph"
	"github.com/teawithsand/uciph/kx"
)

// NewKXEncKey creates new asymmetric Encryptor with key exchange algorithm and symmetric encryption algorithm.
func NewKXEncKey(
	kxGen kx.Gen,
	exchanger kx.KX,
	kxPublicPart []byte,

	// ephemeralEncryptorFactory has to create Encryptor from KX result.
	ephemeralEncryptorFactory func(options interface{}, kxResult []byte) (Encryptor, error),
) (ek EncKey, err error) {
	ek = func(options interface{}) (e Encryptor, err error) {
		// 1. Generate ephemeric KX keypair and process it
		ephemeralKX := &kx.Generated{}
		err = kxGen(options, ephemeralKX)
		if err != nil {
			return
		}

		// 2. Create new ephemeral encryption key
		// same key can be regenerated using ephemeral public part and
		eek, err := exchanger(options, kxPublicPart, ephemeralKX.SecretPart, nil)
		if err != nil {
			return
		}

		rawPK := ephemeralKX.PublicPart
		ephemeralKX = nil // free secret part as it's no longer needed

		intEnc, err := ephemeralEncryptorFactory(options, eek)
		if err != nil {
			return
		}

		e = EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
			// 3. Embbed ephemerical public, so it can be recovered with this public and secret of other side
			// KX is key exchange function, like diffie hellman
			// KX(ephemerical_public, not_available_secret_AKA_secret_key) = KX(remote_public_which_is_known, ephemerical_secret)

			// first chunk is special - includes KX algorithm public
			if len(rawPK) > 0 {
				// TODO(teawithsand): check how appendTo trick works with overlapping slices
				pkLen := len(rawPK)

				// prepend raw KX public + it's length at the beginning
				// note: assumption is that it may have variable length.
				// this way with 4 byte overhead we solve entrie class of problems, which is nice
				// and acceptable IMO
				// It's better than adding another argument.
				appendTo = append(appendTo, 0, 0, 0, 0)
				appendTo = append(appendTo, rawPK[:]...)
				binary.BigEndian.PutUint32(
					appendTo[len(appendTo)-4-len(rawPK):len(appendTo)-len(rawPK)],
					uint32(pkLen),
				)

				// res, err = intEnc.Encrypt(in, appendTo[len(rawPK)+4:]) // and then encrypt message and append it msg(note: slicing of second arg may be omitted)
				res, err = intEnc.Encrypt(in, appendTo)
				if err != nil {
					return
				}

				rawPK = nil
			} else {
				// for other chunks just redirect call
				res, err = intEnc.Encrypt(in, appendTo)
			}
			return
		})

		return
	}

	return
}

// NewKXDecKey creates new DecKey, which is able to reverse transformation done
// by NewKXEncKey.
func NewKXDecKey(
	exchanger kx.KX,
	kxSecretKey []byte,

	// epehemeralDecryptorFactory creates decryptor from key exchange result.
	// Under the hood it should create key from kxResult and return new encryptor for it.
	// It should be complementary to epehemeralEncryptorFactory supplied in NewKXEncKey.
	epehemeralDecryptorFactory func(options interface{}, kxResult []byte) (Decryptor, error),
) (dec DecKey, err error) {
	dec = func(options interface{}) (dec Decryptor, err error) {
		var initDec Decryptor

		dec = DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
			// It's first chunk!
			// We have to parse PK part
			if initDec == nil {
				if len(in) < 4 { // we can do that as it's not streamming decryptor
					err = uciph.ErrCiphertextInvalid
					return
				}
				rawSZ := binary.BigEndian.Uint32(in[:4])
				in = in[4:]

				// if sz is greater than uint32 max length
				if rawSZ > (^uint32(0))>>1 {
					err = uciph.ErrCiphertextInvalid
					return
				}
				// this cast should never overflow now
				sz := int(rawSZ)
				/*
					if sz < 0 {
						panic("It has overflown anyway...")
					}
				*/
				if sz > len(in) {
					err = uciph.ErrCiphertextInvalid
					return
				}

				kxPublicPart := in[:sz]
				in = in[sz:]

				var eek []byte // do not overwrite error...
				eek, err = exchanger(options, kxPublicPart, kxSecretKey, nil)
				if err != nil {
					return nil, err
				}

				initDec, err = epehemeralDecryptorFactory(options, eek)
				if err != nil {
					return nil, err
				}

				res, err = initDec.Decrypt(in, appendTo)
			} else {
				res, err = initDec.Decrypt(in, appendTo)
			}
			return
		})
		return
	}
	return
}
