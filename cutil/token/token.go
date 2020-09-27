package token

import (
	"encoding/base64"
	"fmt"
)

type TokenLoadError struct {
	Err error
}

func (tle *TokenLoadError) Error() string {
	if tle == nil {
		return "<nil>"
	}
	if tle.Err != nil {
		return fmt.Sprintf("uciph/cutil/token: Token loading filed: %s", tle.Err.Error())
	}
	return "uciph/cutil/token: Token loading filed"
}

func (tle *TokenLoadError) Unwrap() error {
	return tle.Err
}

// Manager is something able to issue and load tokens.
type Manager interface {
	IssueToken(data interface{}) (token []byte, err error)
	LoadToken(token []byte) (res interface{}, err error)
}

// Base64Manager wraps other manager and base64 encodes them with encoding it's given.
type Base64Manager struct {
	Manager  Manager
	Encoding base64.Encoding
}

func (m *Base64Manager) IssueToken(data interface{}) (token []byte, err error) {
	token, err = m.Manager.IssueToken(data)
	if err != nil {
		return
	}
	/*
		initialSize := 0
		diff := len(token) - base64.StdEncoding.EncodedLen(len(token))
		for i := 0; i < diff; i++ {
			token = append(token)
		}
		base64.StdEncoding.Encode(token[:0], token[:initialSize])
	*/
	token = []byte(m.Encoding.EncodeToString(token))
	return
}

func (m *Base64Manager) LoadToken(token []byte) (res interface{}, err error) {
	decodedToken, err := m.Encoding.DecodeString(string(token))
	if err != nil {
		err = &TokenLoadError{Err: err}
		return
	}

	res, err = m.Manager.LoadToken(decodedToken)
	return
}
