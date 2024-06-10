import re
import math
import random
from modern import AES_Cipher_Encryption
# repeated functions need to be cited from previous assignment
class Functions:

    def getmsg(self):
        msg = input("Provide the msg for encryption with alphabets: ")
        print("\n")
        while not msg or not self.is_valid_input(msg):
            msg = input("Provide valid msg for encryption with alphabets: ")
            print("\n")
        return msg
    
    def get_decrypt_msg(self):
        msg = input("Provide the msg for decryption with alphabets: ")
        print("\n")
        while not msg or not self.is_valid_input(msg):
            msg = input("Provide valid msg for decryption with alphabets: ")
            print("\n")
        return msg
    
    def is_valid_input(self,input_string):
        pattern = r'^[a-zA-Z ]+$'
        return bool(re.match(pattern, input_string))
    
    def char_to_bitstring(self,character):
        if character == ' ':
            return '00100000'
        return bin(ord(character))[2:].zfill(8)

# Convert a list of bitstrings to their corresponding characters.
    def bitstring_to_char(self,bitstring):
        integer_value = int(bitstring, 2)
        character = chr(integer_value)
        return character 
    
        # Check if the input string is a valid 8-bit binary number.
    def is_valid_binary_input_main(self,input_string):
        pattern = r'^[01]{8}$'
        return bool(re.match(pattern, input_string))

    def is_valid_binary_input(self,input_string):
        pattern = r'^[01]+$'
        return bool(re.match(pattern, input_string))
    
    def primes(self,str_len):
        if str_len <= 0:
            raise ValueError("The integer must be greater than 0.")
    
        factors = []
        if str_len <= 0:
            raise ValueError("The integer must be greater than 0.")
            
        factors = []
         # Find all factors of n
        for i in range(1, int(math.sqrt(str_len)) + 1):
            if str_len % i == 0:
                factors.append(i)
                if i != str_len // i:
                    factors.append(str_len // i)
            
            # Sort factors
        factors.sort()
            
            # Find the closest pair
        min_diff = float('inf')
        closest_pair = (1, str_len)
        for i in range(len(factors) - 1):
            diff = factors[i + 1] - factors[i]
            if diff < min_diff:
                min_diff = diff
                closest_pair = (factors[i], factors[i + 1])
            
        return closest_pair
    
    def transpos_plain_matrix(self, num_rows, num_columns, plain):
        matrix_e = []
        index = 0
        
        for i in range(num_rows):
            sub_matrix = []
            for j in range(num_columns):
                if index < len(plain):
                    sub_matrix.append(plain[index])
                else:
                    sub_matrix.append(None)  # Fill with None or any default value if plain is exhausted
                index += 1
            matrix_e.append(sub_matrix)
        
        return matrix_e
    
    def get_col_key_trans(self,num_col =0, type = "columns"):

        prompt = f"Given there are {num_col} {type}, provide integer values from 0 to {num_col - 1} for the permutation key or type 'None' to use default shuffling permutation: \n"
        
        while True:
            i_text = input(prompt)
            if i_text == "None":
                shuffle_list = list(range(num_col))
                random.shuffle(shuffle_list)
                return shuffle_list
            elif not i_text.isdigit() or not (0 <= int(i_text) < num_col):
                print(f"Invalid input. Provide integer values from 0 to {num_col - 1}.")
            else:
                key_list = []
                while len(key_list) < num_col:
                    i_text = input(f"Enter integer value {len(key_list) + 1}/{num_col}: ")
                    if i_text.isdigit():
                        value = int(i_text)
                        if 0 <= value < num_col:
                            if value in key_list:
                                print("Value already present in list.")
                            else:
                                key_list.append(value)
                        else:
                            print(f"Value out of range. Provide integer values from 0 to {num_col - 1}.")
                    else:
                        print(f"Invalid input. Provide integer values from 0 to {num_col - 1}.")
                return key_list 
            
    def col_reorder(self,matrix, positions):
        # Validate that positions contain valid indices
        num_columns = len(matrix[0])
        if not all(0 <= pos < num_columns for pos in positions):
            raise ValueError("Positions must be within the range of column indices")

        # Validate that the number of positions matches the number of columns
        if len(positions) != num_columns:
            raise ValueError("The number of positions must match the number of columns")

        # Create a new matrix with columns rearranged according to positions
        new_matrix = []
        for row in matrix:
            new_row = [row[pos] for pos in positions]
            new_matrix.append(new_row)
        
        return new_matrix
    
    def matrix_join(self,matrix):
        new_txt = [''.join(row) for row in matrix]
        return new_txt
    
    def words_to_bits(self,word):
        bit_list = []
        for i in word:
            sub_list = []
            bit_string = self.char_to_bitstring(i)
            for j in bit_string:
                sub_list.append(int(j))
            bit_list.append(sub_list)
        return bit_list
    
    def rotate(self,l,n):
        return l[n:] + l[:n]
