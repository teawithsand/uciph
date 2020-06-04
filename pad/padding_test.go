package pad_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/teawithsand/uciph/pad"
)

func TestCanPadMesasges(t *testing.T) {
	assert := func(in, out []byte, sz int) {
		res := pad.IEC78164Padding().Pad(in, sz)
		if len(res) != len(out) || bytes.Compare(res, out) != 0 {
			t.Error(fmt.Sprintf(
				"Invalid test case found:\nGot: %x\nExpected: %x\nSize: %d", res, out, sz,
			))
		}
	}

	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}, []byte{0xaa, 0xbb, 0xcc, 0x80, 0x00}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0x80}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0x80, 0x00, 0x00, 0x00}, 0)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0xdd}, 4)
	assert([]byte{0xaa, 0xbb, 0xcc, 0xdd}, []byte{0xaa, 0xbb, 0xcc, 0xdd}, 10)
}

func TestCanUnpadMessages(t *testing.T) {
	assert := func(in []byte, outIdx int) {
		idx := pad.IEC78164Padding().Unpad(in)
		if idx < 0 && outIdx >= 0 {
			t.Error(fmt.Sprintf(
				"Expected `%x` to be invalid\n", in,
			))
		} else if idx != outIdx {
			t.Error(fmt.Sprintf(
				"Expected `%x` to yield %d\nYielded: %d\n", in, outIdx, idx,
			))
		}
	}

	assert([]byte{0xaa, 0xbb, 0xcc, 0x80, 0x00}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0x80}, 3)
	assert([]byte{0xaa, 0xbb, 0xcc, 0x80, 0x00, 0x00}, 3)
	assert([]byte{0x80, 0x00}, 0)
	assert([]byte{0x80, 0x00, 0x00}, 0)
	assert([]byte{0x80, 0x00, 0x00, 0x00}, 0)
	assert([]byte{}, -1)
	assert([]byte{0xaa}, -1)
	assert([]byte{0xaa, 0xaa, 0xbb}, -1)
}

var useUnpadStuff int

/*
func BenchmarkUnpadMessage(b *testing.B) {
	doBench := func(sz int, upsz int) {
		buf := make([]byte, sz)
		_, err := io.ReadFull(uciph.GetRNG(nil), buf)
		if err != nil {
			b.Error(err)
		}
		for i := len(buf) - upsz; i < len(buf); i++ {
			buf[i] = 0
		}
		buf[len(buf)-upsz] = 0x80

		b.Run(fmt.Sprintf(
			"unpad random %d bytes to %d",
			len(buf),
			uciph.IEC78164Padding.Unpad(buf),
		), func(b *testing.B) {
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				useUnpadStuff = uciph.IEC78164Padding.Unpad(buf)
			}
		})
	}

	doBench(2048, 1024)

	// TODO(teaiwthsand): debug why these are not constant time
	// these should be same
	doBench(1024*10, 1024)
	doBench(1024*10, 1024*3)
	doBench(1024*10, 1024*2)
}
*/
