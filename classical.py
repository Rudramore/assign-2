from pydoc import plain
from numpy import place
from required_functions import Functions
import string
import random

class Caeser_Cipher:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = 0
        self.c_text = c_input

    def encrypt(self):
        cipher_text = ""
        ind = int(self.get_key())
        for i in self.plain:
            if i in string.ascii_lowercase:
                new_ind = self.char_lower_pos_e(i,ind)
                cipher_text = cipher_text + string.ascii_lowercase[new_ind]
            else:
                new_ind = self.char_upper_pos_e(i,ind)
                cipher_text = cipher_text + string.ascii_uppercase[new_ind]
            return cipher_text
    
    def char_lower_pos_e(self,i,ind):
        p_ind = ord(i) - ord('a')
        new_ind = (p_ind+ind) % 26
        return new_ind
    
    def char_upper_pos_e(self,i,ind):
        p_ind = ord(i) - ord('A')
        new_ind = (p_ind+ind) % 26
        return new_ind

# figure out the decryption  
    # def decrypt(self):
    #     plain_text = ""
    #     ind = int(self.get_key())
    #     for i in self.c_text:
    #         if i in string.ascii_lowercase:
    #             new_ind = self.char_lower_pos_d(i,ind)
    #             plain_text = plain_text + string.ascii_lowercase[new_ind]
    #         else:
    #             new_ind = self.char_upper_pos_d(i,ind)
    #             plain_text = plain_text + string.ascii_uppercase[new_ind]
    #         return plain_text
    #     return 
    
    def char_lower_pos_d(self,i,ind):
        p_ind = ord(i) - ord('a')
        new_ind = (26 + p_ind- ind) % 26
        return new_ind
    
    def char_upper_pos_d(self,i,ind):
        p_ind = ord(i) - ord('A')
        new_ind = (26 + p_ind- ind) % 26
        return new_ind

    def get_key(self):
        i_text = input("Provide a key to shift or type None to use default key 3: ")
        print("\n")
        while True:
            if i_text == "None":
                return 3
            elif i_text.isdigit() == False:
                i_text = input("Provide a valid key to shift: ")
                print("\n")
            else:
                return i_text
            
class Permutation_Cipher:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = 0
        self.c_text = c_input
    
    def encrypt(self,plain):
        cipher = ""
        ind = self.get_key(plain)
        new_string = ''.join(cipher[pos] for pos in ind)
        return new_string

    def get_key(self, plain):
        max_index = len(plain) - 1
        prompt = f"Provide integer values from 0 to {max_index} for the permutation key or type 'None' to use default shuffling permutation: \n"
        
        while True:
            i_text = input(prompt)
            if i_text == "None":
                shuffle_list = list(range(len(plain)))
                random.shuffle(shuffle_list)
                return shuffle_list
            elif not i_text.isdigit():
                print(f"Invalid input. Provide integer values from 0 to {max_index}.")
            else:
                key_list = []
                while len(key_list) < len(plain):
                    i_text = input(f"Enter integer value {len(key_list)+1}/{len(plain)}: ")
                    if i_text.isdigit():
                        value = int(i_text)
                        if 0 <= value <= max_index:
                            if value in key_list:
                                print("Value already present in list.")
                            else:
                                key_list.append(value)
                        else:
                            print(f"Value out of range. Provide integer values from 0 to {max_index}.")
                    else:
                        print(f"Invalid input. Provide integer values from 0 to {max_index}.")
                return key_list

# need to figure it out            
    # def decrypt(self,cipher):
    #     plain_t = ""
    #     ind = self.get_key(cipher)
    #     new_string = ''.join(cipher[pos] for pos in ind)
    #     return new_string


class Single_transposition_Cipher:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = 0
        self.c_text = c_input

    def encrypt(self):
        func = Functions()
        num_col = func.primes(len(self.plain))
        num_rows, num_columns = num_col
        str_matrix = func.transpos_plain_matrix(num_rows,num_columns , self.plain)
        key_list = func.get_col_key_trans(num_columns)
        ciph_matrix = func.col_reorder(str_matrix,key_list)
        cip_text = func.matrix_join(ciph_matrix)
        return cip_text

    def decrypt(self):
        return 

class Double_transposition_Cipher:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = 0
        self.c_text = c_input

    def get_row_key_trans(self, num_rows):
        func = Functions()
        row_key_list = func.get_col_key_trans(num_rows, type= "rows")
        return row_key_list

    def row_reorder(self,matrix, positions):
        # Validate that positions contain valid indices
        num_rows = len(matrix[0])
        if not all(0 <= pos < num_rows for pos in positions):
            raise ValueError("Positions must be within the range of column indices")

        # Validate that the number of positions matches the number of rows
        if len(positions) != num_rows:
            raise ValueError("The number of positions must match the number of columns")

        # Create a new matrix with rows rearranged according to positions
        new_matrix = [matrix[pos] for pos in positions]
        
        return new_matrix

class Vigenere_Cipher:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = 0
        self.c_text = c_input

    def encrypt(self):
        func = Functions()
        key = func.getmsg()
        new_key = self.key_text_len_checker(key)
        ciph = ""
        for i in range(len(new_key)):
            if self.plain[i] in string.ascii_lowercase:
                ind = ord(self.plain[i]) - ord('a')
                new_pos = (ind + ord(new_key[i])) % 26
                ciph += string.ascii_lowercase[new_pos]
            else:
                ind = ord(self.plain[i]) - ord('A')
                new_pos = (ind + ord(new_key[i])) % 26
                ciph += string.ascii_uppercase[new_pos]
        return ciph

    def getmsg(self):
        func = Functions()
        while True:
            msg = input("Provide the key for encryption or press enter without string to apply default key: ")
            if not msg:
               return None  # or any appropriate action
            if func.is_valid_input(msg):
                return msg
            else:
                print("Invalid input. Please provide valid input in the format (word1 word2) or (word).")

    def key_text_len_checker(self, key):
        if not key: 
            for i in range(len(self.plain)):
                if self.plain[i] in string.ascii_lowercase:
                    key += random.choice(string.ascii_lowercase)
                else:
                    key += random.choice(string.ascii_uppercase)
            return key
        if len(self.plain) > len(key):
            while len(key) < len(self.plain):
                key += key[:len(self.plain) - len(key)]
            return key[:len(self.plain)]
        elif len(self.plain) < len(key):
            return key[:len(self.plain)]
        else:
            return key
        
    def char_lower_pos_e(self,i,ind):
        p_ind = ord(i) - ord('a')
        new_ind = (p_ind+ind) % 26
        return new_ind
    
    def char_upper_pos_e(self,i,ind):
        p_ind = ord(i) - ord('A')
        new_ind = (p_ind+ind) % 26
        return new_ind



class Classical:
    def __init__(self):
        inp = self.get_user_input()

    def get_user_input(self):
        print("Which encryption would you prfer:")
        print("1) Shift cipher")
        print("2) Permutation cipher")
        print("3) Simple transposition cipher")
        print("4) Double transposition cipher")
        print("5) Vigenere cipher")
        inp =  input("Enter your choice (1,2,3,4,5): ")
        if inp == "1":
            out = self.shift_encrypt_cipher()
        if inp == "2":
            out = self.perm_cipher()
        if inp == "3":
            out = self.simple_transpos_cipher()
        if inp == "4":
            out = self.double_transpos_cipher()
        if inp == "5":
            out = self.vigenere_cipher()
        else:
            print("Invalid Input \n")
            x = input("Enter only either these choices (1,2,3,4,5): ")
            print("\n")

#each function needs a particular kind of input
    def shift_encrypt_cipher(self):
        func = Functions()
        input_p = func.getmsg()
        plain = Caeser_Cipher(p_input=input_p)
        return plain.encrypt()

# need to figure out    
    # def shift_decrypt_cipher(self):
    #     func = Functions()
    #     input_c = func.get_decrypt_msg()
    #     plain = Caeser_Cipher(c_input = input_c)
    #     return plain.decrypt()
    

    def perm_cipher(self):
        return
    
    def simple_transpos_cipher(self):
        return
    
    def double_transpos_cipher(self):
        return
# make sure input and key have both upper and lowercase in the correct positions in the string 
    def vigenere_cipher(self):
        return