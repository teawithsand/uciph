// Package uciph implements common interface for cryptography utilities.
// This way cryptographic algorithms may be swapped easily.
//
// It also solves common tasks like streamming encryption, like files.
package uciph

/*
Overall design:
There are few basic building blocks:
1. EncryptionKey and 2. DecryptionKey
   Input: []byte(in multiple writes) Res: []byte(after each write)
3. SigningKey and 4. VerifyingKey and 5. Hasher
   Input: []byte(in multiple writes) Res: []byte(constant length usually)
6. Key exchange algorithms:
   Input: []byte(once) Res: []byte(once)

Blinded signs and other more advanced and algorithm specific things are not implemented, because the goal is protability between algorithms.
*/