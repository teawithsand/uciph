package pwhash_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/teawithsand/uciph/cbench"
	"github.com/teawithsand/uciph/cutil/pwhash"
)

func doTestArgon2(t *testing.T, options pwhash.Options, ao pwhash.Argon2Options) {
	// TODO(teawithsand): check if pepper is in use
	hasher, verifier := pwhash.Argon2ID(options, ao)

	hash, err := hasher([]byte("Password"))
	if err != nil {
		t.Error(err)
	}

	if len(hash.Salt) > 4 {
		hash1, err := hasher([]byte("Password"))
		if err != nil {
			t.Error(err)
		}
		hash2, err := hasher([]byte("Password"))
		if err != nil {
			t.Error(err)
		}
		if bytes.Compare(hash1.Salt, hash2.Salt) == 0 {
			t.Error("Two salted hashes have same salt")
		} else if bytes.Compare(hash1.Hash, hash2.Hash) == 0 {
			t.Error("Two hashes of same password with different salt are same")
		}
	} else if len(hash.Salt) == 0 {
		hash1, err := hasher([]byte("Password"))
		if err != nil {
			t.Error(err)
		}
		hash2, err := hasher([]byte("Password"))
		if err != nil {
			t.Error(err)
		}
		hash3, err := hasher([]byte("Password3"))
		if err != nil {
			t.Error(err)
		}

		if bytes.Compare(hash1.Hash, hash2.Hash) != 0 {
			t.Error("Two hashes of same password with no salt are not same")
		}
		if bytes.Compare(hash3.Hash, hash1.Hash) == 0 {
			t.Error("Two hashes of different passwords with no salt are same")
		}
	}

	if hash.Version != options.HashVersion {
		t.Error("Hash version mismatch")
	}
	if len(hash.Salt) != options.SaltSize {
		t.Error("Hash has invalid salt")
	}

	eq, err := verifier([]byte("Password"), hash)
	if err != nil {
		t.Error(err)
	} else if !eq {
		t.Error(fmt.Errorf("Argon2 password hash is not same when equal"))
	}

	eq, err = verifier([]byte("Password2"), hash)
	if err != nil {
		t.Error(err)
	} else if eq {
		t.Error(fmt.Errorf("Argon2 password hash same when not equal"))
	}
}

func TestArgon2(t *testing.T) {
	doTestArgon2(t, pwhash.Options{
		HashVersion: 1,
	}, pwhash.Argon2Options{})

	doTestArgon2(t, pwhash.Options{
		HashVersion: 1,
		Pepper:      []byte("Fancy peper 1"),
	}, pwhash.Argon2Options{})

	doTestArgon2(t, pwhash.Options{
		HashVersion: 1,
		SaltSize:    8,
		Pepper:      []byte("Fancy peper 1"),
	}, pwhash.Argon2Options{})
}

func BenchmarkArgon2(b *testing.B) {
	e := cbench.PWHashBenchEngine{
		Fac: func(rc cbench.PWHashBenchRunConfig) pwhash.Hasher {
			h, _ := pwhash.Argon2ID(pwhash.Options{
				HashVersion: 1,
				SaltSize:    8,
				Pepper:      []byte("adadadadadadadadadadadadadadadad"), // 32 bytes pepper
			}, rc.Data.(pwhash.Argon2Options))

			return h
		},
		Config: cbench.PWHashBenchConfig{
			Runs: []cbench.PWHashBenchRunConfig{
				cbench.PWHashBenchRunConfig{
					Name: "DefaultConfig",
					Data: pwhash.Argon2Options{},
				},
				cbench.PWHashBenchRunConfig{
					Name: "Config:T-1:M-32MB",
					Data: pwhash.Argon2Options{
						Time:    2,
						Memory:  32 * 1024,
						Threads: 1,
					},
				},
				cbench.PWHashBenchRunConfig{
					Name: "Config:T-1:M-64MB",
					Data: pwhash.Argon2Options{
						Time:    2,
						Memory:  64 * 1024,
						Threads: 1,
					},
				},
				cbench.PWHashBenchRunConfig{
					Name: "Config:T-2:M-32MB",
					Data: pwhash.Argon2Options{
						Time:    2,
						Memory:  32 * 1024,
						Threads: 1,
					},
				},
				cbench.PWHashBenchRunConfig{
					Name: "Config:T-2:M-64MB",
					Data: pwhash.Argon2Options{
						Time:    2,
						Memory:  64 * 1024,
						Threads: 1,
					},
				},
			},
		},
	}

	e.RunPWHashBenchmark(b)
}
