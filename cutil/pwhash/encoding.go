package pwhash

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrHashTooLong = errors.New("uciph/cutil/pwhash: Given hash is too long and can't be encoded with uciph's PWHash format")
var ErrSaltTooLong = errors.New("uciph/cutil/pwhash: Given salt is too long and can't be encoded with uciph's PWHash format")

type PWHashDecodeError struct {
	Err error
}

func (err *PWHashDecodeError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Err == nil {
		return "uciph/cutil/pwhash: PWHash decoding filed"
	}
	return fmt.Sprintf("uciph/cutil/pwhash: PWHash decoding filed: %s", err.Err.Error())
}
func (err *PWHashDecodeError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// PWHash represents password hash with additonal options, useful for password hashing.
type PWHash struct {
	Version uint64 `json:"version,omitempty"`
	Hash    []byte `json:"hash"`
	Salt    []byte `json:"salt"`
}

// EncodeToString encodes this PWHash to string.
func (h *PWHash) EncodeToString() (res string, err error) {
	raw, err := h.EncodeToBytes()
	if err != nil {
		return
	}
	res = base64.StdEncoding.EncodeToString(raw)
	return
}

// DecodeString decodes PWHash encoded with PWHash.EncodeToString.
func (h *PWHash) DecodeString(bb string) (err error) {
	raw, err := base64.StdEncoding.DecodeString(bb)
	if err != nil {
		err = &PWHashDecodeError{Err: err}
		return
	}
	err = h.DecodeBytes(raw)
	return
}

// DecodeBytes decodes given bytes to PWHash it's called on.
// These bytes should be created with PWHash.EncodeToBytes.
func (h *PWHash) DecodeBytes(bb []byte) (err error) {
	h.Version = 0
	h.Hash = nil
	h.Salt = nil

	defer func() {
		_, isPHDE := err.(*PWHashDecodeError)
		if err != nil && !isPHDE {
			err = &PWHashDecodeError{Err: err}
		}
	}()
	r := bytes.NewReader(bb)
	var buf [8]byte
	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return
	}

	sz, err := r.ReadByte()
	if err != nil {
		return
	}

	hash := make([]byte, int(sz))
	_, err = io.ReadFull(r, hash[:])
	if err != nil {
		return
	}

	h.Hash = hash

	sz, err = r.ReadByte()
	if err != nil {
		return
	}

	salt := make([]byte, int(sz))
	_, err = io.ReadFull(r, salt[:])
	if err != nil {
		return
	}

	h.Salt = salt

	if r.Len() != 0 {
		err = &PWHashDecodeError{}
	}

	return
}

// EncodeToBytes encodes this password hash to bytes.
// Password hash encoded this way may be decoded later.
func (h *PWHash) EncodeToBytes() (dst []byte, err error) {
	b := bytes.NewBuffer(nil)

	if len(h.Hash) > 255 {
		err = ErrHashTooLong
		return
	}
	if len(h.Salt) > 255 {
		err = ErrSaltTooLong
		return
	}
	// calls below should never fail...

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], h.Version)

	_, err = b.Write(buf[:])
	if err != nil {
		return
	}
	_, err = b.Write([]byte{byte(len(h.Hash))})
	if err != nil {
		return
	}
	_, err = b.Write(h.Hash)
	if err != nil {
		return
	}
	_, err = b.Write([]byte{byte(len(h.Salt))})
	if err != nil {
		return
	}
	_, err = b.Write(h.Salt)
	if err != nil {
		return
	}

	dst = b.Bytes()
	return
}
