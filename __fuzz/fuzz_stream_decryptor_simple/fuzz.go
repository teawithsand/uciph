package fuzzpackage

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/teawithsand/uciph/enc"
)

func Fuzz(data []byte) int {
	ed := enc.NewDefaultStreamDecryptor(enc.BlankDecryptor(), bytes.NewReader(data))
	_, err := io.Copy(ioutil.Discard, ed)
	if err != nil {
		return 0
	}
	err = ed.Close()
	if err != nil {
		return 0
	}

	return 1
}
