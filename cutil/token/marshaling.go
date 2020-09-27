package token

import "encoding/json"

// Marshaler is responsible for serializing token data into bytes.
type Marshaler = func(in interface{}) (out []byte, err error)

// Unmarshaler is responsible for deserializing token data from bytes.
type Unmarshaler = func(data []byte) (res interface{}, err error)

// JSONMarshaler marsahls any type of token data as JSON.
// It can be reverted for specific type with JSONUnmarshaler.
var JSONMarshaler Marshaler = json.Marshal

// JSONUnmarshaler unmarshals given type of token data using factory.
// Factory has to return POINTER TYPE of deserialized struct in order to make it work.
func JSONUnmarshaler(fac func() interface{}) Unmarshaler {
	return Unmarshaler(func(data []byte) (res interface{}, err error) {
		res = fac()
		err = json.Unmarshal(data, res)
		return
	})
}

// MarshalingManager is simplest possible token manager.
// The only thing it does it marshalling token with
type MarshalingManager struct {
	Marshaler   Marshaler
	Unmarshaler Unmarshaler
}

// IssueToken serializes data, and encrypts it.
func (m *MarshalingManager) IssueToken(data interface{}) (token []byte, err error) {
	token, err = m.Marshaler(data)
	return
}

// LoadToken decrypts data, and deserializes it.
func (m *MarshalingManager) LoadToken(token []byte) (res interface{}, err error) {
	res, err = m.Unmarshaler(token)
	if err != nil {
		err = &TokenLoadError{err}
	}
	return
}
