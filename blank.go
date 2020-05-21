package uciph

var BlankEncryptor Encryptor = EncryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})

var BlankDecryptor Decryptor = DecryptorFunc(func(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
})
