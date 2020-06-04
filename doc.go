// Package uciph is cryptographic library, which was created to solve common problems.
// It reuses existing packages from golang standard library and golang x packages.
//
// Notes about subpackages:
// * enc is encryption package. It handles both symmetric and asymmetric encryption.
// * pad is padding package. It handles message padding(s).
// * sig (NOTE: hash functions live here) implements signing and (H)MACs and hash functions.
// * kx implements key exchange algorithms.
// * rand is randomness package. It implements rngs.
// * util implements variety of low level utilities useful when creating other constructions.
//
// Also one more note: Slice overlapping rule
// When function takes two argument called appendTo with type []byte it may get two values:
// 1. nil value. This one causes new result buffer to be allocated.
// 2. in[:0] where in is first argument given. This one causes in-place action and overrides at least part of data
//    and returns reference to the processed data
// Otherwise ErrInvalidOverlap erorr is returned OR non-in-place operation is executed depending on implementation.
package uciph
