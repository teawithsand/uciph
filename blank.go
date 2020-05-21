package uciph

// BlankEncryptor is encryptor which is essentially NO-OP.
// It appends in to res.
var BlankEncryptor Encryptor = EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})

// BlankDecryptor is decryptor which is essentially NO-OP.
// It appends in to res.
var BlankDecryptor Decryptor = DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})
