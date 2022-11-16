import gmpy2 
from gmpy2 import mpz
import time
import random
from utils import RSA
import base64
from Crypto.Util import number

key_size = 512 #bits
block_size = 120
#Generating keys for CA public and private

p = mpz(number.getStrongPrime(key_size))
q = mpz(number.getStrongPrime(key_size))
while(p == q):
    p = mpz(number.getStrongPrime(key_size))
    q = mpz(number.getStrongPrime(key_size))
n = gmpy2.mul(p,q)
phi_n = gmpy2.mul((p-1),(q-1))
e = mpz(2)

while(gmpy2.gcd(e,phi_n) != 1):
    e = gmpy2.add(e,1)
d = gmpy2.invert(e,phi_n)

f = open("CA/skCA.txt","w")
f.writelines([str("p=")+str(p)+"\n",str("q=")+str(q)+"\n",str("n=")+str(n)+str("\n"),str("e=")+str(e)+"\n",str("d=")+str(d)])
f.close()

f = open("public_keys/pkCA.txt","w")
f.writelines([str("e=")+str(e)+"\n",str("n=")+str(n)+"\n"])
f.close()


##Generating keys for userA
#secret key
p = mpz(number.getStrongPrime(key_size))
q = mpz(number.getStrongPrime(key_size))
while(p<=q):
    p = mpz(number.getStrongPrime(key_size))
    q = mpz(number.getStrongPrime(key_size))
n = mpz(p*q)
phi_n = mpz((p-1)*(q-1))
e = mpz(2)
while(gmpy2.gcd(e,phi_n) != 1):
    e = gmpy2.add(e,1)
d = gmpy2.invert(e,phi_n)

#handing secret key to A
f = open("USER_A/skA.txt","w")
f.writelines([str("p=")+str(p)+"\n",str("q=")+str(q)+"\n",str("n=")+str(n)+str("\n"),str("e=")+str(e)+"\n",str("d=")+str(d)])
f.close()

#signing public key of A
f = open("public_keys/pkA.txt","w")
m = str(e)+str(n)
s,d_block_size = RSA.sign(m,"CA/skCA.txt",block_size)
s = s.encode('utf-8')
f.writelines([str("e=")+str(e)+"\n",str("n=")+str(n)+"\n",str("s=")+str(s.hex())+"\n",str("d_blocksize=")+str(d_block_size)])
f.close()

##Generating keys for userB
#secret key
p = mpz(number.getStrongPrime(key_size))
q = mpz(number.getStrongPrime(key_size))
while(p<=q):
    p = mpz(number.getStrongPrime(key_size))
    q = mpz(number.getStrongPrime(key_size))
n = mpz(p*q)
phi_n = mpz((p-1)*(q-1))
e = mpz(2)
while(gmpy2.gcd(e,phi_n) != 1):
    e = gmpy2.add(e,1)
d = gmpy2.invert(e,phi_n)

#handing secret key to B
f = open("USER_B/skB.txt","w")
f.writelines([str("p=")+str(p)+"\n",str("q=")+str(q)+"\n",str("n=")+str(n)+str("\n"),str("e=")+str(e)+"\n",str("d=")+str(d)])
f.close()

#signing public key of B
f = open("public_keys/pkB.txt","w")
m = str(e)+str(n)
s,d_block_size = RSA.sign(m,"CA/skCA.txt",block_size)
s = s.encode('utf-8')
f.writelines([str("e=")+str(e)+"\n",str("n=")+str(n)+"\n",str("s=")+str(s.hex())+"\n",str("d_blocksize=")+str(d_block_size)])
f.close()