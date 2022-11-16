
def encrypt(plain_text,key):
    encrypted_text = ""
    i = 0
    for each_char in plain_text:
        encrypted_text = encrypted_text + chr((ord(each_char)+ord(key[i]))%256)
        i = (i+1)%len(key)
    return encrypted_text

def decrypt(encrypted_text,key):
    decrypted_text = ""
    i = 0
    for each_char in encrypted_text:
        decrypted_text = decrypted_text + chr((ord(each_char)-ord(key[i]))%256)
        i = (i+1)%len(key)
    return decrypted_text