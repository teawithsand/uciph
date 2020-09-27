package token_test

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/teawithsand/uciph/cutil/token"
	"github.com/teawithsand/uciph/enc"
	"github.com/teawithsand/uciph/rand"
)

type TokenManagerTestConfig struct {
	Fac             func() token.Manager
	IsSigning       bool
	IsStrictSigning bool
}

type TestTokenData struct {
	IssuedAt time.Time `json:"iat"`
	Text     string    `json:"cnt"`
}

func (ttd *TestTokenData) GetIssuedAt() time.Time {
	return ttd.IssuedAt
}

var TestTokenDataUnmarshaler = token.JSONUnmarshaler(func() interface{} {
	return &TestTokenData{}
})
var TTDManager token.Manager = &token.MarshalingManager{
	Marshaler:   token.JSONMarshaler,
	Unmarshaler: TestTokenDataUnmarshaler,
}

func NewTTD(text string) *TestTokenData {
	return &TestTokenData{
		IssuedAt: time.Now(),
		Text:     text,
	}
}

func DoTestTokenManager(t *testing.T, cfg TokenManagerTestConfig) {
	fac := cfg.Fac
	t.Run("ISSUE_AND_LOAD_SAME", func(t *testing.T) {
		tm := fac()
		d1 := NewTTD("d1")
		// d2 := NewTTD("d2")
		token, err := tm.IssueToken(d1)
		if err != nil {
			t.Error(err)
			return
		}

		ld1, err := tm.LoadToken(token)
		if err != nil {
			t.Error(err)
			return
		}

		pld1 := ld1.(*TestTokenData)

		if d1.Text != pld1.Text {
			t.Error(fmt.Errorf("Token data mismatch: %+#v ;;; %+#v", *d1, *pld1))
		}
	})

	if cfg.IsSigning || cfg.IsStrictSigning {
		t.Run("ISSUE_AND_LOAD_WITH_DIFFERENT_MANAGER", func(t *testing.T) {
			tm1 := fac()
			tm2 := fac()

			d1 := NewTTD("d1")

			token1, err := tm1.IssueToken(d1)
			if err != nil {
				t.Error(err)
				return
			}

			_, err = tm2.LoadToken(token1)
			if err == nil {
				t.Error("No error, but expected one")
			}
		})
	}
}

func TestMarshalingManager(t *testing.T) {
	DoTestTokenManager(t, TokenManagerTestConfig{
		Fac: func() token.Manager {
			return &token.MarshalingManager{
				Marshaler:   token.JSONMarshaler,
				Unmarshaler: TestTokenDataUnmarshaler,
			}
		},
	})
}

func TestEncryptingManager(t *testing.T) {
	kg := func() []byte {
		var arr [32]byte
		_, err := io.ReadFull(rand.DefaultRNG(), arr[:])
		if err != nil {
			t.Error(err)
			return nil
		}

		return arr[:]
	}

	// XOR encryption is fine for testing
	// No need for more advanced encryption method here
	DoTestTokenManager(t, TokenManagerTestConfig{
		Fac: func() token.Manager {
			key := kg()
			return &token.EncryptingManager{
				Manager: TTDManager,
				DecFac: func() enc.Decryptor {
					return enc.XORDecryptor(key)
				},
				EncFac: func() enc.Encryptor {
					return enc.XOREncryptor(key)
				},
			}
		},
	})
}

// TODO(teaiwthsand): test signing, test expiring
