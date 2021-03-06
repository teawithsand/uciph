# μCiph 
μCiph is crypto library created in order to:
1. Solve common problems, like stream encryption to encrypt big files
2. Allow easy cryptosystem swapping in case some turns out to be broken
3. Allows composite cipher creation(cipher/hash function created from many different hash functions) (NIY)

## The goal:
Provide wrappers for commonly used cryptographic "primitives" and allow easy swapping of these when it's required.

It does not implements algoritms itself, except:
* Message padding scheme(ISO/IEC 7816-4) (is NOT constant time yet)

What it does implement right now:
#### Various end user utiltiies
* stream(io.Reader/io.Writer) encryption, unlike TLS suitable for file encryption
* Token management - with signing, encryption and expiration
* Password hash format - with support for versioning 

#### Encryption(symmetric)
* ChaCha20Poly1305 cipher
* AES 128/192/256 GCM cipher
* ChaCha20 PRNG

#### Encryption(asymmetric)
* Key exchange to asymmetric encryption(with symmetric algorithm)

#### Signing
* Ed25519
* RSA

### Others
* golang stdlib crypto hash functions(abstractable wrappers)
* HMAC using golang stdlib
* ISO/IEC 7816-4 Padding
* Simple hash based PoW algorithm
* Blank polyfils for most of the things
* Streamming encryption designed for files(unlike SSL, use SSL for network streams)
* RNG and PRNG utils
* Nonce counter maintaining unique nonces (not constant time, usually does not have to be)