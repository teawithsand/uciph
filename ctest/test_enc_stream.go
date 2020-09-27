package ctest

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

func DoTestStreamED(
	t *testing.T,
	encFac func(w io.Writer) enc.StreamEncryptor,
	decFac func(r io.Reader) enc.StreamDecryptor,
) {

	testChunks := func(t *testing.T, chunks [][]byte) (err error) {
		dst := bytes.NewBuffer(nil)

		encryptor := encFac(dst)
		for _, c := range chunks {
			_, err = encryptor.Write(c)
			if err != nil {
				return err
			}
		}
		err = encryptor.Close()
		if err != nil {
			return err
		}

		decryptor := decFac(bytes.NewReader(dst.Bytes()))

		outputData, err := ioutil.ReadAll(decryptor)
		if err != nil {
			return err
		}

		err = decryptor.Close()
		if err != nil {
			return err
		}

		inputData := make([]byte, 0)

		for _, c := range chunks {
			inputData = append(inputData, c...)
		}

		if bytes.Compare(inputData, outputData) != 0 {
			return errors.New("Encrypted data differs from encrypted")
		}

		return
	}

	t.Run("Enc:1MB_1C_Dec:NDEF", func(t *testing.T) {
		chunks, err := cbench.MakeTestChunks(rand.DefaultRNG(), 1024*1024)
		if err != nil {
			t.Error(err)
			return
		}
		testChunks(t, chunks)
	})

	t.Run("Enc:8MB_1C_Dec:NDEF", func(t *testing.T) {
		chunks, err := cbench.MakeTestChunks(rand.DefaultRNG(), 1024*1024*8)
		if err != nil {
			t.Error(err)
			return
		}
		testChunks(t, chunks)
	})

	t.Run("Enc:8MB_4C_Dec:NDEF", func(t *testing.T) {
		chunks, err := cbench.MakeTestChunks(rand.DefaultRNG(), cbench.EqualChunkSizes(1024*1024*8, 4)...)
		if err != nil {
			t.Error(err)
			return
		}
		testChunks(t, chunks)
	})
	t.Run("Enc:1KB_1024C_Dec:NDEF", func(t *testing.T) {
		chunks, err := cbench.MakeTestChunks(rand.DefaultRNG(), cbench.EqualChunkSizes(1024, 1024)...)
		if err != nil {
			t.Error(err)
			return
		}
		testChunks(t, chunks)
	})

	t.Run("CustomTest_1", func(t *testing.T) {
		chunks, err := cbench.MakeTestChunks(rand.DefaultRNG(), 0, 0, 0, 0, 1, 2, 3, 8, 1234, 0, 0, 0, 234)
		if err != nil {
			t.Error(err)
			return
		}
		testChunks(t, chunks)
	})
}

// TODO(teawithsand): benchmarks for stream encryptor/decryptor
