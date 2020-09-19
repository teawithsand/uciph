package kx_test

import (
	"bytes"
	"testing"

	"github.com/teawithsand/uciph/kx"
)

func DoTestKX(t *testing.T, gen kx.Gen, exchanger kx.KX) {
	t.Run("Works", func(t *testing.T) {
		var lastDst []byte
		for i := 0; i < 100; i++ {
			kx1 := &kx.Generated{}
			err := gen(nil, kx1)
			if err != nil {
				t.Error(err)
				return
			}

			kx2 := &kx.Generated{}
			err = gen(nil, kx2)
			if err != nil {
				t.Error(err)
				return
			}

			dst1, err := exchanger(nil, kx1.PublicPart, kx2.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}
			dst2, err := exchanger(nil, kx2.PublicPart, kx1.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}

			if len(dst1) == 0 || len(dst2) == 0 {
				t.Error("No key returned")
				return
			}

			if bytes.Compare(dst1, dst2) != 0 {
				t.Error("KX algorithm does not work, it does not create same key from one secret and one public part")
				return
			}

			if len(lastDst) == 0 {
				lastDst = dst1
			} else {
				if bytes.Compare(lastDst, dst2) == 0 {
					t.Error("KX algorithm gives same result after swapping both KX pairs")
					return
				}
			}
		}
	})

	t.Run("DoesDiffer_TwoPartsSwapped", func(t *testing.T) {
		var lastDst []byte

		for i := 0; i < 100; i++ {
			kx1 := &kx.Generated{}
			err := gen(nil, kx1)
			if err != nil {
				t.Error(err)
				return
			}

			kx2 := &kx.Generated{}
			err = gen(nil, kx2)
			if err != nil {
				t.Error(err)
				return
			}

			dst1, err := exchanger(nil, kx1.PublicPart, kx2.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}
			dst2, err := exchanger(nil, kx2.PublicPart, kx1.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}

			if len(dst1) == 0 || len(dst2) == 0 {
				t.Error("No key returned")
				return
			}

			if len(lastDst) == 0 {
				lastDst = dst1
			} else {
				if bytes.Compare(lastDst, dst2) == 0 {
					t.Error("KX algorithm does not give different result after rotating both KX parts")
					return
				}
			}
		}
	})

	t.Run("DoesDiffer_OnePartSwapped", func(t *testing.T) {
		var lastDst []byte

		kx1 := &kx.Generated{}
		err := gen(nil, kx1)
		if err != nil {
			t.Error(err)
			return
		}

		for i := 0; i < 100; i++ {
			kx2 := &kx.Generated{}
			err = gen(nil, kx2)
			if err != nil {
				t.Error(err)
				return
			}

			dst1, err := exchanger(nil, kx1.PublicPart, kx2.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}
			dst2, err := exchanger(nil, kx2.PublicPart, kx1.SecretPart, nil)
			if err != nil {
				t.Error(err)
				return
			}

			if len(dst1) == 0 || len(dst2) == 0 {
				t.Error("No key returned")
				return
			}

			if len(lastDst) == 0 {
				lastDst = dst1
			} else {
				if bytes.Compare(lastDst, dst2) == 0 {
					t.Error("KX algorithm does not give different result after rotating one KX part")
					return
				}
			}
		}
	})

}
