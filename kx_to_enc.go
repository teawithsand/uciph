package uciph

import "encoding/binary"

// NewKXParsedEncKey creates new parsed encryption key, which may be used to create encryptors
// from any key exchange scheme.
//
// Note: It uses ephemerical keypair for each encryption, so enc key options passed may include something like
// "always use nonce counter" checked
func NewKXParsedEncKey(
	kxGen KXGen,
	pkx PubKX,
	kxp KXParser,
	// epehemeralEncryptorFactory creates encryptor from key exchange result.
	// Under the hood it should create key from kxResult and return new encryptor for it.
	epehemeralEncryptorFactory func(kxResult []byte) (Encryptor, error),
) (enc ParsedEncKey, err error) {
	enc = ParsedEncKeyFunc(func(options EncKeyOptions) (enc Encryptor, err error) {
		// 1. Generate ephemeric KX keypair and process it
		rawPK, rawSK, err := kxGen.GenKX(options)
		if err != nil {
			return
		}
		sk, err := kxp.ParseSecKX(rawSK)
		if err != nil {
			return
		}
		rawNewKey, err := sk.MixWithPub(pkx, nil, nil)
		if err != nil {
			return
		}

		// 2. Create new ephemeral encryption key
		/*
			epek, err := ekp.ParseEncKey(rawNewKey)
			if err != nil {
				return
			}
		*/

		intEnc, err := epehemeralEncryptorFactory(rawNewKey)
		if err != nil {
			return
		}

		enc = EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
			// 3. Embbed ephemerical public, so it can be recovered with this public and secret of other side
			// KX is key exchange function, like diffie hellman
			// KX(ephemerical_public, not_available_secret) = KX(remote_public_which_is_known, ephemerical_secret)

			// first chunk is special - includes KX algorithm public
			if len(rawPK) > 0 {
				// TODO(teawithsand): check how appendTo trick works with overlapping slices
				pkLen := len(rawPK)
				// prepend raw KX public + it's length at the beginning
				// note: assumption is that it may have variable length.
				// this way with 4 byte overhead we solve entrie class of problems, which is nice
				// and acceptable IMO
				// It's better than adding another argument, which requires
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
				res, err = intEnc.Encrypt(in, appendTo[len(rawPK):])
			}
			return
		})
		return
	})
	return
}

// NewKXParsedDecKey creates new ParsedDecKey, which is able to reverse transformation done
// by NewKXParsedEncKey.
func NewKXParsedDecKey(
	kxGen KXGen,
	skx SecKX,
	kxp KXParser,
	// epehemeralDecryptorFactory creates decryptor from key exchange result.
	// Under the hood it should create key from kxResult and return new encryptor for it.
	// It should be complementary to epehemeralEncryptorFactory supplied in NewKXParsedEncKey.
	epehemeralDecryptorFactory func(kxResult []byte) (Decryptor, error),
) (dec ParsedDecKey, err error) {
	dec = ParsedDecKeyFunc(func(options DecKeyOptions) (dec Decryptor, err error) {
		var intDec Decryptor
		dec = DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
			// It's first chunk!
			// We have to parse PK part
			if intDec == nil {
				if len(in) < 4 {
					err = ErrCiphertextInvalid
					return
				}
				rawSZ := binary.BigEndian.Uint32(in[:4])
				in = in[4:]

				// if sz is greater than uint32 max length
				if rawSZ > (^uint32(0))>>1 {
					err = ErrCiphertextInvalid
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
					err = ErrCiphertextInvalid
					return
				}

				pubKX := in[:sz]
				in = in[sz:]

				parsedPubKX, err := kxp.ParsePubKX(pubKX)
				if err != nil {
					return nil, err
				}

				rawKXData, err := skx.MixWithPub(parsedPubKX, nil, nil)
				if err != nil {
					return nil, err
				}

				intDec, err = epehemeralDecryptorFactory(rawKXData)
				if err != nil {
					return nil, err
				}

				res, err = intDec.Decrypt(in, appendTo)
			} else {
				res, err = intDec.Decrypt(in, appendTo)
			}
			return
		})
		return
	})
	return
}
