package fuzzpackage

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

func Fuzz(data []byte) int {
	var sizes []int

	if len(data) < 1 {
		return -1
	}

	sizesCount := int(data[0])
	data = data[1:]

	for i := 0; i < sizesCount; i++ {
		if len(data) < 2 {
			return -1
		}

		sz := binary.BigEndian.Uint16(data[:2])
		sizes = append(sizes, int(sz))

		data = data[2:]
	}

	ed := enc.NewDefaultStreamDecryptor(enc.BlankDecryptor(), bytes.NewReader(data))

	chunks, err := cbench.MakeTestChunks(rand.ZeroRNG(), sizes[:]...)
	if err != nil {
		panic(err)
	}

	for _, c := range chunks {
		_, err := ed.Read(c) // TODO(teawithsand): assertions on rdSz
		if err != nil {
			return 0
		}
	}

	_, err = io.Copy(ioutil.Discard, ed)
	if err != nil {
		return 0
	}
	err = ed.Close()
	if err != nil {
		return 0
	}

	return 1
}
