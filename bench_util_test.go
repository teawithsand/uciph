package uciph_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/teawithsand/uciph"
)

type encDecTest struct {
	Name  string
	Cases [][]byte
}

func (edt *encDecTest) AddCase(d []byte) *encDecTest {
	edt.Cases = append(edt.Cases, d)
	return edt
}
func (edt *encDecTest) AutoName() {
	sum := 0
	for _, c := range edt.Cases {
		sum += len(c)
	}
	edt.Name = fmt.Sprintf("%d chunks of total size %d bytes", len(edt.Cases), sum)
}

var edtRes []byte

func (edt *encDecTest) RunRNG(b *testing.B, rngf func() io.Reader) {
	sum := 0
	for _, c := range edt.Cases {
		sum += len(c)
	}

	b.Run(edt.Name, func(b *testing.B) {
		b.SetBytes(int64(sum))

		rng := rngf()
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			for _, c := range edt.Cases {
				_, err := io.ReadFull(rng, c)
				if err != nil {
					b.Error(err)
				}
			}
		}
	})
}

func (edt *encDecTest) RunEnc(b *testing.B, ef func() uciph.Encryptor) {
	sum := 0
	for _, c := range edt.Cases {
		sum += len(c)
	}

	b.Run(edt.Name, func(b *testing.B) {
		b.SetBytes(int64(sum))

		encs := make([]uciph.Encryptor, b.N)
		for i := 0; i < len(encs); i++ {
			encs[i] = ef()
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			// new encryptor per bench run
			e := encs[n]
			for _, c := range edt.Cases {
				var err error
				edtRes, err = e.Encrypt(c, nil)
				if err != nil {
					b.Error(err)
				}
			}
		}
	})

	b.Run(edt.Name+" in place", func(b *testing.B) {
		b.SetBytes(int64(sum))

		encs := make([]uciph.Encryptor, b.N)
		for i := 0; i < len(encs); i++ {
			encs[i] = ef()
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			// new encryptor per bench run
			e := encs[n]
			for _, c := range edt.Cases {
				// note: it's encrypting different data on each iteration
				var err error
				edtRes, err = e.Encrypt(c, c[:0])
				if err != nil {
					b.Error(err)
				}
			}
		}
	})
}

func (edt *encDecTest) RunDec(
	b *testing.B,
	// If ef is nil input data is not encrypted.
	// TODO(teawithsand): merge these two factories into one producing correspoinding enc/decryptors
	ef func() uciph.Encryptor,
	df func() uciph.Decryptor,
) {
	if ef != nil {
		for i, c := range edt.Cases {
			e := ef()
			var err error
			edt.Cases[i], err = e.Encrypt(c, c[:0])
			if err != nil {
				b.Error(err)
			}
		}
	}

	sum := 0
	for _, c := range edt.Cases {
		sum += len(c)
	}

	// This pass should left input unmodified
	b.Run(edt.Name, func(b *testing.B) {
		b.SetBytes(int64(sum))

		encs := make([]uciph.Decryptor, b.N)
		for i := 0; i < len(encs); i++ {
			encs[i] = df()
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			// new encryptor per bench run
			e := encs[n]
			for _, c := range edt.Cases {
				var err error
				edtRes, err = e.Decrypt(c, nil)
				if err != nil {
					b.Error(err)
				}
			}
		}
	})

	// and this should modify it but it's fine
	b.Run(edt.Name+" in place", func(b *testing.B) {
		b.SetBytes(int64(sum))

		encs := make([]uciph.Decryptor, b.N)
		for i := 0; i < len(encs); i++ {
			encs[i] = df()
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			// new encryptor per bench run
			e := encs[n]
			for _, c := range edt.Cases {
				// note: it's encrypting different data on each iteration
				var err error
				edtRes, err = e.Decrypt(c, c[:0])
				if err != nil {
					b.Error(err)
				}
			}
		}
	})
}

func benchmarkRNG(b *testing.B, rngf func() io.Reader) {
	tests := make([]encDecTest, 0)
	{
		t := encDecTest{}
		t.AddCase(make([]byte, 1024*1024*8)).AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 8; i++ {
			t.AddCase(make([]byte, 1024*1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 512; i++ {
			t.AddCase(make([]byte, 1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	for _, t := range tests {
		t.RunRNG(b, rngf)
	}
}

func benchmarkEncryptor(b *testing.B, ef func() uciph.Encryptor) {
	tests := make([]encDecTest, 0)
	{
		t := encDecTest{}
		t.AddCase(make([]byte, 1024*1024*8)).AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 8; i++ {
			t.AddCase(make([]byte, 1024*1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 512; i++ {
			t.AddCase(make([]byte, 1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	for _, t := range tests {
		t.RunEnc(b, ef)
	}
}

// TODO(teawithsand): use this and implement decryptor benchmarks
func benchmarkDecryptor(b *testing.B, ef func() uciph.Encryptor) {
	tests := make([]encDecTest, 0)
	{
		t := encDecTest{}
		t.AddCase(make([]byte, 1024*1024*8)).AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 8; i++ {
			t.AddCase(make([]byte, 1024*1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	{
		t := encDecTest{}
		for i := 0; i < 512; i++ {
			t.AddCase(make([]byte, 1024))
		}
		t.AutoName()
		tests = append(tests, t)
	}
	for _, t := range tests {
		t.RunEnc(b, ef)
	}
}
