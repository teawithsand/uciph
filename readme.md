### Work in progress
It's not ready yet.

# μCiph 
μCiph is crypto library created:
1. Solve common problems, like stream encryption to encrypt big files
2. Allow easy cryptosystem swapping in case some turns out to be broken
3. Allows composite cipher creation(cipher/hash function created from many different hash functions) (NIY)

It does not implements algoritms itself, except:
1. Message padding scheme(ISO/IEC 7816-4) (is implemented using constant time operations).