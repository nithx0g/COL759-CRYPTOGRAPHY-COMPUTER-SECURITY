* To install required modules run "pip3 install -r requirements.txt"
* Required python3.8+ to run this code.
* All files need to be in the same directory.
* All required files are submitted with the code.

-------- PART-1 -----------

<<<<<<<<<<<<<<<--------ENCRYPTION-------->>>>>>>>>>>>>>>
* To run "python3 encryption.py"
* Input files
  1)plaintext.txt = contains the input message
  2)key.txt = is randomly generated within code and stored in this file,also provided the necessary comments in the code for manual key input
* Output files
  1)ciphertext.txt = contains the ciphertext

<<<<<<<<<<<<<<----------DECRYPTION-------->>>>>>>>>>>>>>
* To run "python3 decryption.py"
* Input files
  1)key.txt
  2)ciphertext.txt
* Output files
  None
* Decrypted text is printed to the terminal


-------- PART-2 -----------

* To run "python3 part2.py"
* Input files
  1)plaintext.txt
  2)ciphertext.txt
  3)key.txt = to verify the found key length
* Output files
  None
* To assume n^2 known characters ,appropriate code is used ( assumed first 150 characters are known)
* functions used
  -> main : program execution starts here
* Helper functions used
  -> matrix_to_text
  -> text_to_matrix
  -> inverse
  -> decrypt
  -> index_of_coincidence
