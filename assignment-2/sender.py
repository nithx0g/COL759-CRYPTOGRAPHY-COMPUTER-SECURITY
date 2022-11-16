from utils import RSA,vignere
import re
import gmpy2 
from gmpy2 import mpz
import base64
import codecs

block_size = 120

plain_text = open("inp.txt","r").read().rstrip()
vigKey = open("USER_A/K.txt","r").read().rstrip()

Cs = vignere.encrypt(plain_text,vigKey)

f = open("public_keys/pkB.txt","r")
lines = f.readlines()
f.close()

for line in lines:
    arr = line.split("=")
    name = arr[0]
    if(name == "d_blocksize"):
        d_blocksize_B = int(arr[1])
    if(name == "e"):
        e = str(arr[1]).rstrip()
    if(name == "n"):
        n = str(arr[1]).rstrip()
    if(name == "s"):
        s = str(arr[1]).rstrip()

#verifying public key of B
s_bytes = bytes(s.rstrip(),encoding='utf-8')
s_string = codecs.decode(s_bytes,"hex")
s = str(s_string,'utf-8')
keys = RSA.verify_sign(s,"public_keys/pkCA.txt",d_blocksize_B,block_size)

if(keys == e + n):
    print("public key of B is verified")
else:
    print("public key of B is corrupted")
    exit()

#encrypting the message and symmetric key
intermediate_cipher_text,d_block_size_A_for_C=RSA.sign(Cs,"USER_A/skA.txt",block_size)
C,d_block_size_B_for_C = RSA.encrypt(intermediate_cipher_text,"public_keys/pkB.txt",block_size)

intermediate_cipher_key,d_block_size_A_for_K=RSA.sign(vigKey,"USER_A/skA.txt",block_size)
K_,d_block_size_B_for_K = RSA.encrypt(intermediate_cipher_key,"public_keys/pkB.txt",block_size)

#saving the encrypted message and symmetric key
f = open("enc.txt","w")
f.writelines(["C="+str(C.encode('utf-8').hex())+"\n","K_="+str(K_.encode('utf-8').hex())+"\n","d_block_size_A_for_C="+str(d_block_size_A_for_C)+"\n","d_block_size_A_for_K="+str(d_block_size_A_for_K)+"\n","d_block_size_B_for_C="+str(d_block_size_B_for_C)+"\n","d_block_size_B_for_K="+str(d_block_size_B_for_K)])
f.close()

print("Message sent to B(saved in enc.txt)")

