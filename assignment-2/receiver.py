from utils import RSA,vignere
import codecs

block_size = 120
C = ""
K_ = ""

#reading the encrypted message and key
f = open("enc.txt","r")
lines = f.readlines()
f.close()

values = {}
for line in lines:
    arr = line.split("=")
    if(arr[0] == "C"):
        C_bytes = bytes(arr[1].rstrip(),encoding='utf-8')
        C_string = codecs.decode(C_bytes,"hex")
        C = str(C_string,'utf-8')
    elif(arr[0] == "K_"):
        K_bytes = bytes(arr[1].rstrip(),encoding='utf-8')
        K_string = codecs.decode(K_bytes,"hex")
        K_ = str(K_string,'utf-8')
    else:
        values[arr[0]] = int(arr[1])
d_block_size_A_for_C = values["d_block_size_A_for_C"]
d_block_size_A_for_K = values["d_block_size_A_for_K"]
d_block_size_B_for_C = values["d_block_size_B_for_C"]
d_block_size_B_for_K = values["d_block_size_B_for_K"]

# To verify public key of A
f = open("public_keys/pkA.txt","r")
lines = f.readlines()
f.close()
for line in lines:
    arr = line.split("=")
    name = arr[0]
    if(name == "d_blocksize"):
        d_blocksize_A = int(arr[1])
    if(name == "e"):
        e = str(arr[1]).rstrip()
    if(name == "n"):
        n = str(arr[1]).rstrip()
    if(name == "s"):
        s = str(arr[1]).rstrip()

s_bytes = bytes(s.rstrip(),encoding='utf-8')
s_string = codecs.decode(s_bytes,"hex")
s = str(s_string,'utf-8')
keys = RSA.verify_sign(s,"public_keys/pkCA.txt",d_blocksize_A,block_size)
if(keys == e + n):
    print("public key of A is verified")
else:
    print("public key of A is corrupted")

#Decrypting the message and key
intermediate_text = RSA.decrypt(C,"USER_B/skB.txt",d_block_size_B_for_C,block_size)
intermediate_key = RSA.decrypt(K_,"USER_B/skB.txt",d_block_size_B_for_K,block_size)
Cs = RSA.verify_sign(intermediate_text,"public_keys/pkA.txt",d_block_size_A_for_C,block_size)
K = RSA.verify_sign(intermediate_key,"public_keys/pkA.txt",d_block_size_B_for_K,block_size)

print("--------------------Vignere Key--------------------")
print(K)
print("-----------------Decrypted message--------------------")
#Decrypting the vignere cipher
M = vignere.decrypt(Cs,K)
print(M)

f = open("dec.txt","w")
f.write(M)
f.close()
