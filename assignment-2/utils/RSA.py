import gmpy2 
from gmpy2 import mpz

def encrypt(message,key,block_size):
    f = open(key,"r")
    lines = f.readlines()
    f.close()
    values = {}
    #Getting values from the key file
    for line in lines:
        arr = line.split("=")
        name = arr[0]
        if(name == 's'):
            value = arr[1]
        elif(name == 'e_blocksize' or name == 'd_blocksize'):
            name = line.split("=")[0]
            value = line.split("=")[1]
        else:
            value = mpz(line[2:(len(line))].rstrip())
        values[name] = value
    encrypted_text = ""
    e = mpz(values['e'])
    n = mpz(values['n'])
    #dividing message into blocks
    blocks = [(message[i:i+block_size]) for i in range(0,len(message),block_size)]
    
    encrypted_text = ""
    encrypted_text_blocks = []
    C_=[]
    max_decryption_block_size = 1
    for block in blocks:
        M = mpz(0)
        C = mpz(0)
        for i in range(0,len(block)):
            M = ord(block[i]) + gmpy2.mul(M,256)  #converting message block to integer
        C = gmpy2.powmod(M,e,n)  # Encrypting the message
        C_.append(C)
        text = ""
        while(C):  #Converting integer to text
            text = text+chr(C%256)
            C = gmpy2.f_div(C,256)
        encrypted_text_blocks.append(text)
    max_C = mpz(max(C_))
    while(max_C):
        max_decryption_block_size = max_decryption_block_size + 1 # to find max block size
        max_C = gmpy2.f_div(max_C,256)
    for block in encrypted_text_blocks:
        encrypted_text = encrypted_text + block + chr(0)*(max_decryption_block_size-len(block)) #add padding
    return encrypted_text,max_decryption_block_size

def decrypt(message,key,d_block_size,e_block_size):
    
    f = open(key,"r")
    lines = f.readlines()
    f.close()

    values = {}
    for line in lines:
        name = line[0]
        value = mpz(line[2:len(line)])
        values[name] = value
    d = mpz(values["d"])
    p = mpz(values["p"])
    q = mpz(values["q"])
    e = mpz(values["e"])
    n = mpz(values["n"])
    blocks = [(message[i:i+d_block_size]) for i in range(0,len(message),d_block_size)]  #dividing cipher text into blocks

    #add padding if necessary
    blocks[len(blocks)-1] = blocks[len(blocks)-1] + chr(0)*(d_block_size - len(blocks[len(blocks)-1]))
    decrypted_text = ""
    dP = gmpy2.invert(e,p-1)
    dQ = gmpy2.invert(e,q-1)
    qInv = gmpy2.invert(q,p)
    
    for block in blocks:
        C = mpz(0)
        for i in range(len(block)):
            C = ord(block[len(block)-i-1]) + gmpy2.mul(C,256)
        
        m1 = gmpy2.powmod(C,dP,p)
        m2 = gmpy2.powmod(C,dQ,q)
        #Garner's formula
        h = gmpy2.powmod(gmpy2.mul(qInv,gmpy2.sub(m1,m2)),1,p)
        m = gmpy2.add(m2,gmpy2.mul(h,q))
        m_text = ""
        
        #convert integer to text
        for i in range(e_block_size):
            m_text =chr(m%256) + m_text
            m = gmpy2.f_div(m,256)
        decrypted_text = decrypted_text + m_text.lstrip(chr(0)) # removing the padding added
    return decrypted_text

def sign(message,key,block_size):
    f = open(key,"r")
    lines = f.readlines()
    f.close()
    values = {}

    #reading values from key file
    for line in lines:
        name = line[0]
        value = mpz(line[2:len(line)])
        values[name] = value
    d = mpz(values["d"])
    p = mpz(values["p"])
    q = mpz(values["q"])
    e = mpz(values["e"])

    # diving message into blocks
    blocks = [(message[i:i+block_size]) for i in range(0,len(message),block_size)]
    signature = ""
    signature_blocks = []
    dP = gmpy2.invert(e,p-1)
    dQ = gmpy2.invert(e,q-1)
    qInv = gmpy2.invert(q,p)

    S_=[]
    for block in blocks:
        M = mpz(0)
        for i in range(len(block)):
            M = ord(block[i]) + gmpy2.mul(M,256)
        s1 = gmpy2.powmod(M,dP,p)
        s2 = gmpy2.powmod(M,dQ,q)
        h = gmpy2.powmod(gmpy2.mul(qInv,gmpy2.sub(s1,s2)),1,p)
        s = gmpy2.add(s2,gmpy2.mul(h,q))
        s_text = ""
        
        S_.append(s)
        #converting signature integer to text
        while(s):
            s_text = s_text + chr(s%256)
            s = gmpy2.f_div(s,256)
        signature_blocks.append(s_text)

    max_value = mpz(max(S_))
    max_block_size = 1
    #finding the max block size
    while(max_value):
        max_block_size = max_block_size + 1
        max_value = gmpy2.f_div(max_value,256)
    
    #add padding to signature block
    for block in signature_blocks:
        signature = signature + block + chr(0)*(max_block_size-len(block)) # to add padding
    return signature,max_block_size
    
def verify_sign(message,key,d_block_size,e_block_size):
    f = open(key,"r")
    lines = f.readlines()
    f.close()
    values = {}

    #reading values from key file
    for line in lines:
        arr = line.split("=")
        name = arr[0]
        if(name == 's'):
            value = arr[1]
        elif(name == 'd_blocksize'):
            name = line.split("=")[0]
            value = line.split("=")[1]
        else:
            value = mpz(line[2:(len(line))].rstrip())
        values[name] = value
    
    decrypted_sig = ""
    e = mpz(values['e'])
    n = mpz(values['n'])

    #dividing signature into blocks
    blocks = [(message[i:i+d_block_size]) for i in range(0,len(message),d_block_size)]
    
    decrypted_sig = ""
    for block in blocks:
        S = mpz(0)
        for i in range(0,len(block)):
            S = ord(block[len(block)-1-i]) + gmpy2.mul(S,256)
        
        m_text = ""
        M = gmpy2.powmod(S,e,n)
        #converting decrypted integer into text
        for i in range(e_block_size):
            m_text =chr(M%256) + m_text
            M = gmpy2.f_div(M,256)
        decrypted_sig = decrypted_sig + m_text.lstrip(chr(0))# removing the padding added

    return decrypted_sig