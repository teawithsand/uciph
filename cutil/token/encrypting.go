package token

import "github.com/teawithsand/uciph/enc"

// EncryptingManager uses EncFac and DecFac to encrypt/decrypt marshaled data.
// EncFac and DecFac should use AEAD encryptors in order not to allow tampering with token contents.
type EncryptingManager struct {
	Manager Manager

	EncFac func() enc.Encryptor
	DecFac func() enc.Decryptor
}

// IssueToken serializes data, and encrypts it.
func (m *EncryptingManager) IssueToken(data interface{}) (token []byte, err error) {
	res, err := m.Manager.IssueToken(data)
	if err != nil {
		return
	}
	token, err = m.EncFac().Encrypt(res, nil)
	return
}

// LoadToken decrypts data, and deserializes it.
func (m *EncryptingManager) LoadToken(token []byte) (res interface{}, err error) {
	decToken, err := m.DecFac().Decrypt(token, nil)
	if err != nil {
		return
	}
	res, err = m.Manager.LoadToken(decToken)
	return
}
