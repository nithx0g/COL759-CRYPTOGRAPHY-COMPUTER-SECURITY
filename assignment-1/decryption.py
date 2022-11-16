import numpy as np
import math
from sympy import Matrix
from sympy.matrices import determinant

ciphertext=open("ciphertext.txt","r").read().rstrip() # reading ciphertext from text file
al=list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
print("---------------CIPHER TEXT------------------")
print(ciphertext)
plaintext_decrypted=""

key = np.loadtxt("key.txt").astype(np.int)  # loading key from text file

print("----------------KEY-------------------")
print(key)


adjoint = Matrix(key).adjugate() #finding adjoint
determinant = round(np.linalg.det(key)) #finding determinant
determinant = pow(int(determinant%26),-1,26) # modular inverse of determinant
key_inverse = adjoint*determinant 
key_inverse = key_inverse % 26
key_inverse = np.array(key_inverse).astype(np.int)

print("-------------KEY INVERSE-------------")
print(key_inverse)

# matrix multiplication to find plain text
k=0
l=list(ciphertext)
while(1):
    arr=[0]*len(key_inverse)
    inp=[]
    for i in range(len(key_inverse)):
        inp=inp+[int(al.index(l[k]))]
        k=k+1
    for i in range(len(key_inverse)):
        sum=0
        for j in range(len(key_inverse)):
            sum=sum+int(key_inverse[i][j]*inp[j])
        arr[i]=sum%26
        plaintext_decrypted=plaintext_decrypted+al[arr[i]]
    if(len(plaintext_decrypted)==len(ciphertext)):
        break

print("------------PLAIN TEXT DECRYPTED---------")
print(plaintext_decrypted)   
    
    
    
