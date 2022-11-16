import math
import re
from typing import Text
import numpy as np
from numpy.core.fromnumeric import shape
from sympy import Matrix


plain_text = "".join(re.findall("[a-zA-z]",open("plaintext.txt","r").read().rstrip())) #reading plaintext from file and removing unwanted characters
plain_text = plain_text.upper()

cipher_text = open("ciphertext.txt","r").read().rstrip() #reading cipher text from file

def main(): 
    IOC_list=[] #list to store IOC values
    keysize_found = 0
    for key_size in range(2,11):
        plain_matrix_known = text_to_matrix(plain_text,key_size,0) # 0 means to convert only first n^2 characters
        cipher_matrix_known = text_to_matrix(cipher_text,key_size,0)

        #windowing method to find valid plain text matrix
        k=1
        while(k*key_size <= 150):#assume 150 known characters
            det = int(round(np.linalg.det(plain_matrix_known)))%26
            if(det == 0 or math.gcd(det,26) != 1): #checks for valid plain text matrix
                plain_matrix_known = text_to_matrix(plain_text[k*key_size:len(plain_text)],key_size,0)
                cipher_matrix_known = text_to_matrix(cipher_text[k*key_size:len(cipher_text)],key_size,0)
            else:
                break
            k=k+1
        
        if(det == 0 or math.gcd(det,26) != 1): #if not found within 150 characters
            print("No valid plain text matrix found within 150 characters")
        
        key=np.matmul(cipher_matrix_known,inverse(plain_matrix_known)%26)%26  #calculating key
        plain_text_decrypted = decrypt(cipher_text,key,key_size)  #decrypting entire cipher_text

        IOC = index_of_coincidence(plain_text_decrypted)
        if( IOC > 0.06 and IOC < 0.07 and keysize_found==0):
            key_found = key
            IOC_found = IOC
            keysize_found = key_size
        IOC_list.append(IOC)
    
    print("key size found:",keysize_found)
    key = np.loadtxt("key.txt")
    print("original key size:",shape(key)[0])
    print("-------key found--------")
    print(key_found)
    print("Index of coincidence:",IOC_found)


# function to convert matrix to string
def matrix_to_text(matrix):
    text = ""
    for row in matrix.transpose(): # to convert columnwise to rowwise
        for i in row:
            text = text + chr(i+65)  # 65 to convert it to ascii value
    return text

# function to convert string to matrix
# all = 1 convert whole text to matrix
# all = 0 convert first n^2 characters to matrix
def text_to_matrix(message,key_size,all):
    if all == 1:
        if len(message)%key_size != 0:
            message = message + 'X'*(key_size-len(message)%key_size)
        columns =   len(message)//key_size
        matrix = np.zeros([columns,key_size],dtype=int)
        i=0;j=0
        for alphabet in message:
            matrix[i][j] = ord(alphabet) - 65
            j=j+1
            if j==key_size:
                j=0
                i=i+1
        return matrix.transpose() # to convert to column-wise from row-wise
    
    # all != 1 implies we assume we only know first n^2 characters
    matrix = np.zeros([key_size,key_size],dtype=int)
    temp=0
    for i in range(0,key_size):
        for j in range(0,key_size):
            matrix[i][j] = ord(message[temp]) - 65
            temp = temp + 1
    
    return matrix.transpose() # to convert to column-wise from row-wise

#function to find inverse of a matrix
def inverse(matrix):
    determinant = int(round(np.linalg.det(matrix))%26)
    if determinant == 0:
        print("Obtained key not valid for key size:",shape(matrix)[0])
        return matrix
    i=0
    try:
        determinant = pow(determinant,-1,26) # finding inverse modulo of determinant
    except:
        print("Obtained key not valid for key size:",shape(matrix)[0])
    
    adjoint = Matrix(matrix).adjugate()

    inverse = adjoint*determinant
    inverse = inverse%26
    return np.array(inverse).astype(np.int)

#function to decrypt entire cipher text
def decrypt(cipher_text,key,key_size):

    cipher_text_matrix = text_to_matrix(cipher_text,key_size,1) # 1 ==> to convert all ciphertext characters to matrix
    plain_text_matrix = np.matmul(inverse(key),cipher_text_matrix)%26
    plain_text_decrypted = matrix_to_text(plain_text_matrix)

    return plain_text_decrypted

#function to calculate index of coincidence
def index_of_coincidence(text):
    
    #remove padding
    for c in reversed(text):
        if c == "X":
            text = text[0:len(text)-1]
            continue
        break
    frequency={}
    for i in range(0,26):
        frequency[i] = 0  #intialising all frequencies to zero
    for c in text:
        i = ord(c)-65 
        frequency[i] = frequency[i] + 1

    IC=0
    for i in range(0,26):
        IC = IC + (frequency[i]*(frequency[i]-1))/(len(text)*(len(text)-1))
    return IC


main()