import numpy as np
import random
import math
from numpy.core.arrayprint import dtype_is_implied


inputstr=""
ciphertext=""
n=0

message = open("plaintext.txt","r").read().rstrip().upper() # taking plain text from text file
keysize = random.randint(2,10) # choosing a random key size

determinant = 0
while(determinant == 0 or math.gcd(determinant,26) != 1 ): # checks for valid key
    key_matrix = np.random.randint(0,26,size=(keysize,keysize))  # generating a random valid key
    determinant = int(round(np.linalg.det(key_matrix)%26))
key=key_matrix

# To use manual key , edit key values in key.txt and uncomment below lines
#key = np.loadtxt("key.txt").astype(np.int)
#keysize = shape(key)[0]

print("---------------KEY---------------")
print(key)
np.savetxt("key.txt",key.astype(np.int),fmt="%d") #saving key file locally

#filtering unwanted characters
al=list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
for i in message:
    if i in al:
        inputstr+=i

# To add padding
if(len(inputstr)%keysize!=0):
    i=len(inputstr)%keysize
    j= keysize - i
    inputstr=inputstr+'X'*j

message = inputstr
print("----------------------PLAIN TEXT---------------------")
print(message)



k=0
l=list(inputstr) #converting to list for accessing elements using index

# matrix multiplication to generate cipher text
while(1):
    arr=[0]*len(key)
    inp=[]
    for i in range(len(key)):
        inp=inp+[int(al.index(l[k]))]
        k=k+1
    for i in range(len(key)):
        sum=0
        for j in range(len(key)):
            sum=sum+key[i][j]*inp[j]
        arr[i]=sum%26
        ciphertext=ciphertext+al[arr[i]]
    if(len(ciphertext)==len(message)):
        break

print("-------------CIPHER TEXT--------------")
print(ciphertext)
open("ciphertext.txt","w").write(ciphertext)