package enc

var blankEncryptor = EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})

// BlankEncryptor is encryptor which is essentially NO-OP.
// It's NOT SECURE AND SHOULD NOT BE USED IN PRODUCTION. It has been crated for testing purposes.
func BlankEncryptor() Encryptor {
	return blankEncryptor
}

var blankDecryptor = DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})

// BlankDecryptor is decryptor which is essentially NO-OP.
// It's NOT SECURE AND SHOULD NOT BE USED IN PRODUCTION. It has been crated for testing purposes.
func BlankDecryptor() Decryptor {
	return blankDecryptor
}

// XOREncryptor creates new encryptor which simply xors input with key given.
// It's NOT SECURE AND SHOULD NOT BE USED IN PRODUCTION. It has been crated for testing purposes.
// If key length is zero it returns blank encryptor.
func XOREncryptor(key []byte) Encryptor {
	if len(key) == 0 {
		return BlankEncryptor()
	}
	i := 0
	return EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		for _, b := range in {
			appendTo = append(appendTo, key[i]^b)
			i++
			if i >= len(key) {
				i = 0
			}
		}
		res = appendTo
		return
	})
}

// XORDecryptor creates new decryptor which simply xors input with key given.
// It's NOT SECURE AND SHOULD NOT BE USED IN PRODUCTION. It has been crated for testing purposes.
// If key length is zero it returns blank decryptor.
func XORDecryptor(key []byte) Decryptor {
	if len(key) == 0 {
		return BlankDecryptor()
	}
	i := 0
	return DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
		// xor encryption is decryption as well
		// it's same code
		for _, b := range in {
			appendTo = append(appendTo, key[i]^b)
			i++
			if i >= len(key) {
				i = 0
			}
		}
		res = appendTo
		return
	})
}
