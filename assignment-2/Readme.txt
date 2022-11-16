
Requirements:
python 3+
=> gmpy2
=> pycryptodomex

File Structure:

Directories:
1) public_keys: contains all the public keys
2) USER_A: contains secret key of user A and symmetric key
3) USER_B: contains secret key of user B and symmetric key
4) CA: contains secret key of CA
5) utils: contains RSA.py and vignere.py ,code for implementing RSA and vignere cipher

Files:
1) CA.py: contains code for key generation with digital signature
2) sender.py: contains code for encryption at the sender
3) receiver.py: contains code for decryption at the receiver
4) Inp.txt: contains input message
5) enc.txt: contains encrypted message given by the sender
6) dec.txt: contains decrypted message produced by the receiver
