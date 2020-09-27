package token

import (
	"bytes"
	"encoding/binary"

	"github.com/teawithsand/uciph/sig"
)

// TODO(teawithand): some wrapper for underlying sign invalid error from uciph here
// var ErrInvalidSign = errors.New("uciph/cutil/token: Token sign is not valid")

// SigningManger uses singer fac and verifier fac in order to verify if token has valid sign or not.
type SigningManger struct {
	Manager Manager

	SignerFac   func() sig.Signer
	VerifierFac func() sig.Verifier
}

// IssueToken serializes data, and encrypts it.
func (m *SigningManger) IssueToken(data interface{}) (token []byte, err error) {
	res, err := m.Manager.IssueToken(data)
	if err != nil {
		return
	}

	signer := m.SignerFac()
	_, err = signer.Write(res)
	if err != nil {
		return
	}

	sign, err := signer.Finalize(nil)
	if err != nil {
		return
	}

	token = make([]byte, 9)

	signSizeVarint := binary.PutUvarint(token, uint64(len(sign)))
	token = token[:signSizeVarint]
	token = append(token, sign...)
	token = append(token, res...)
	return
}

// LoadToken decrypts data, and deserializes it.
func (m *SigningManger) LoadToken(token []byte) (res interface{}, err error) {
	rd := bytes.NewReader(token)
	signSizeVarint, err := binary.ReadUvarint(rd)
	if err != nil {
		return
	}

	signVarintSize := len(token) - rd.Len()

	// won't overflow signed int but really enough
	if signSizeVarint > 1024*1024*1024 || int(signSizeVarint) > len(token)-signVarintSize {
		err = &TokenLoadError{} // TODO(teaiwthsand): specialize error kind here
		return
	}

	sign := token[signVarintSize : signVarintSize+int(signSizeVarint)]
	tokenData := token[signVarintSize+int(signSizeVarint):]

	verifier := m.VerifierFac()
	_, err = verifier.Write(tokenData)
	if err != nil {
		return
	}

	err = verifier.Verify(sign)
	if err != nil {
		err = &TokenLoadError{Err: err}
		return
	}

	res, err = m.Manager.LoadToken(tokenData)
	if err != nil {
		return
	}

	return
}
