### Work in progress
It's not ready yet.

# μCiph 
μCiph is crypto library created:
1. Solve common problems, like stream encryption to encrypt big files
2. Allow easy cryptosystem swapping in case some turns out to be broken (TODO: more cryptosystems)
3. Allows composite cipher creation(cipher/hash function created from many different hash functions) (NIY)

Non goals:
1. Despite the name, simplicity is non-goal.
This library is designed more to allow almost any possible crpytosystem.
For this reason there is some boilerplate, which is required in some cryptosystem and not in others, however
it has to be written always.

It does not implements algoritms itself, except:
1. Message padding scheme(ISO/IEC 7816-4) (is implemented using constant time operations).

What it does implement right now:
1. Curve25519 Key exchange
2. ChaCha20Poly1305 key cipher
3. ChaCha20 PRNG
4. Key exchange to asymmetric encryption, with symmetric algorithm.
5. Ed25519 Signing
6. golang stdlib crypto hash functions
7. HMAC using golang stdlib
8. ISO/IEC 7816-4 Padding(constant time)