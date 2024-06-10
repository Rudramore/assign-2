from ssl import _Cipher
import string
from regex import R
from required_functions import Functions
import itertools
from numpy import bitwise_and, string_
import random

class DES_Cipher_Encryption:
    
    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.c_text = c_input
        self.key = ""
    
    def encrypt(self):
        func = Functions()
        start_words= func.words_to_bits(self.plain)
        
        first_perm = self.init_perm(start_words)

        len_half = len(first_perm) //2
        left_half = first_perm[:len_half]
        left_half_new = list(itertools.chain.from_iterable(left_half))
        right_half = first_perm[len_half:]
        right_half_new = list(itertools.chain.from_iterable(right_half))
        init_key_left, init_key_right = self.key_schedule_p1(self.key)
        for i in range(1,17):
            f_function_bit_list = self.main_f_func(right_half_new,init_key_left, init_key_right,i)
            xor_result_main = self.f_func_xor(left_half_new,f_function_bit_list)
            left_half_new = right_half_new
            right_half_new = xor_result_main
        
        final_cipher_bit = self.fin_perm(left_half_new,right_half_new)
        final_cipher_8_bit = [final_cipher_bit[i:i+8] for i in range(0, len(final_cipher_bit), 8)]
        final_cipher_char_list = []
        for j in range(len(final_cipher_8_bit)):
            out_bit = ''.join(map(str, final_cipher_8_bit[i]))
            out_val = func.bitstring_to_char(out_bit)
            final_cipher_char_list.append(out_val)
        final_cipher = ''.join(final_cipher_char_list)
        return final_cipher

        
#----------------------------x---------------------------
#first round

    def init_perm(self, word_list):
        pre_mat = [[58,50,42,34,26,18,10,2], [60,52,44,36,28,20,12,4],
                    [62,54,46,38,30,22,14,6], [64,56,48,40,32,24,16,8],
                    [57,49,41,33,25,17,9,1], [59,51,43,35,27,19,11,3],
                    [ 61,53,45,37,29,21,13,5], [63,55,47,39,31,23,15,7]]
        
        new_iperm = [[] for _ in range(len(pre_mat))]
        for i in range(len(pre_mat)):
            for j in range(len(pre_mat[i])):
                bit_position = pre_mat[i][j] - 1  # Adjust for 0-based index
                bit_value = word_list[bit_position // 8][bit_position % 8]
                new_iperm[i].append(bit_value)
        return new_iperm

#-----------------------x-----------------------------------
#inbetween round
    def expansion(self,r_half):
        expansion_table = [
    [32, 1, 2, 3, 4, 5],
    [4, 5, 6, 7, 8, 9],
    [8, 9, 10, 11, 12, 13],
    [12, 13, 14, 15, 16, 17],
    [16, 17, 18, 19, 20, 21],
    [20, 21, 22, 23, 24, 25],
    [24, 25, 26, 27, 28, 29],
    [28, 29, 30, 31, 32, 1]]
        expanded_bits = []
        for row in expansion_table:
            for bit_position in row:
                expanded_bits.append(r_half[bit_position - 1])  # Adjust for 0-based index
        return expanded_bits
    
    def f_func_xor(self,bit_list,round_key):
        xored_list = []
        for i in range(len(bit_list)):
            val = bit_list[i] ^ round_key[i]
            xored_list.append(val)
        return xored_list
    
    def f_func_compres(self,big_list):
        perm_format = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
        new_bit_list = []
        six_bit_list = [big_list[i:i+6] for i in range(0, len(big_list), 6)]
        for i in range(len(six_bit_list)):
            row_val_bit = str(six_bit_list[i][0])+str(six_bit_list[i][-1])
            # binary to integer calculation
            row_val = int(row_val_bit,2) + 1
            col_val_bit = ''.join(map(six_bit_list[i][1:-1], col_val_bit))
            col_val = int(col_val_bit,2) + 1
            new_val = perm_format[row_val][col_val]
            new_val_bit = bin(new_val)[2:]
            sub_list = [int(digit) for digit in new_val_bit]
            new_bit_list.append(sub_list)
        return new_bit_list
    
    def f_func_perm(self,big_list):
        perm_format = [
  [16, 7, 20, 21, 29, 12, 28, 17],
  [1, 15, 23, 26, 5, 18, 31, 10],
  [2, 8, 24, 14, 32, 27, 3, 9],
  [19, 13, 30, 6, 22, 11, 4, 25]
    ]
        permutated_bits = []
        for row in perm_format:
            for bit_position in row:
                permutated_bits.append(big_list[bit_position - 1])  # Adjust for 0-based index
        return permutated_bits
    
    #main f function
    def main_f_func(self,r_half,left_key, right_key, rounds):
        new_right_bit_list = self.expansion(r_half)
        new_round_key = self.key_schedule_transform(left_key, right_key, rounds)
        expans_xor_list = self.f_func_xor(new_right_bit_list,new_round_key)
        after_compression_list = self.f_func_compres(expans_xor_list)
        f_func_bits = self.f_func_perm(after_compression_list)
        return f_func_bits

#--------------------------x-----------------------------------
#final round
    def fin_perm(self, left_half_final, right_half_final):
        pre_mat = [[40, 8, 48, 16, 56, 24, 64, 32],
    [39, 7, 47, 15, 55, 23, 63, 31],
    [38, 6, 46, 14, 54, 22, 62, 30],
    [37, 5, 45, 13, 53, 21, 61, 29],
    [36, 4, 44, 12, 52, 20, 60, 28],
    [35, 3, 43, 11, 51, 19, 59, 27],
    [34, 2, 42, 10, 50, 18, 58, 26],
    [33, 1, 41, 9, 49, 17, 57, 25]]
        
        final_list =[]
        final_list.append(right_half_final)
        new_latest_right = left_half_final

        for i in new_latest_right:
            final_list.append(i)
        
        final_cipher_list = []
        for row in pre_mat:
            for bit_position in row:
                final_cipher_list.append(final_list[bit_position - 1])  # Adjust for 0-based index
        return final_cipher_list


    #-------------------------------x------------------------------
    #key schedule

#---------------------------x--------------------------
#pre transform// needs to be part of encrypt
    def key_schedule_p1(self,words):
        func = Functions()
        k_bit_list = func.words_to_bits(words)
        pc_1 = self.key_s_perm(k_bit_list)
        new_key_list = list(itertools.chain.from_iterable(pc_1))
        new_len = len(new_key_list) //2
        r_half = new_key_list[:new_len]
        l_half = new_key_list[new_len:]
        return l_half,r_half

    def key_s_perm(self,bit_list):
        pc_1 = [
    [57, 49, 41, 33, 25, 17, 9, 1],
    [58, 50, 42, 34, 26, 18, 10, 2],
    [59, 51, 43, 35, 27, 19, 11, 3],
    [60, 52, 44, 36, 63, 55, 47, 39],
    [31, 23, 15, 7, 62, 54, 46, 38],
    [30, 22, 14, 6, 61, 53, 45, 37],
    [29, 21, 13, 5, 28, 20, 12, 4]]
        expanded_bits = []
        for row in pc_1:
            for bit_position in row:
                expanded_bits.append(bit_list[bit_position - 1])  # Adjust for 0-based index
        return expanded_bits        
#-----------------------------------x---------------------------
#each new round// transform

    def key_s_rounds(self,left_h,right_h,round):
        func = Functions()
        if round in [1,2,9,16]:
            new_left = func.rotate(left_h,1)
            new_right = func.rotate(right_h,1)
        else:
            new_left = func.rotate(left_h,2)
            new_right = func.rotate(right_h,2)
        return new_left,new_right
    
    def key_schedule_perm2(self,bit_list):
        pc_2 = [
    [14, 17, 11, 24, 1, 5, 3, 28],
    [15, 6, 21, 10, 23, 19, 12, 4],
    [26, 8, 16, 7, 27, 20, 13, 2],
    [41, 52, 31, 37, 47, 55, 30, 40],
    [51, 45, 33, 48, 44, 49, 39, 56],
    [34, 53, 46, 42, 50, 36, 29, 32]
    ]
        compressed_bits = []
        for row in pc_2:
            for bit_position in row:
                compressed_bits.append(bit_list[bit_position - 1])  # Adjust for 0-based index
        return compressed_bits  

    #main call for f function key use
    def key_schedule_transform(self,left_half, right_half,round_cnt):
        left_bit_list,right_bit_list = self.key_s_rounds(left_half, right_half,round_cnt)
        new_key_bit_list= left_bit_list + right_bit_list
        round_key = self.key_schedule_perm2(new_key_bit_list)
        return round_key


class AES_Cipher_Encryption:

    def __init__(self,c_input = "", p_input = "") :
        self.plain = p_input
        self.key = ""
        self.c_text = c_input
        self.key_length = 0

    def encrypt(self):
        func = Functions()
        bit_list = func.words_to_bits(self.plain)
        first_bit_list = list(itertools.chain.from_iterable(bit_list))

        #key schedule here to get whole list
        key_list = self.key_schedule_list()

        # loop for eac h round based on the key length (byte sub, shift row, mix col, join)
        if self.key_length == 128:
            k1 = key_list[0]
            k1.extend(key_list[1])
            k1.extend(key_list[2])
            k1.extend(key_list[3])
            key_transform = self.xor_lists(first_bit_list,k1 )
            for i in range(1,11):
                s_sub_list = self.s_sub(key_transform)
                shifted_matrix= self.shift_row(s_sub_list)
                col_shift_matrix = self.mix_columns(shifted_matrix)
                diffusion_list = self.join_list(col_shift_matrix)
                k1 = key_list[(4*i)+0]
                k1.extend(key_list[(4*i)+1])
                k1.extend(key_list[(4*i)+2])
                k1.extend(key_list[(4*i)+3])
                key_transform = self.xor_lists(diffusion_list,k1 )
            new_cipher_list = self.divide_chunks(key_transform,8)
            cipher = ""
            for i in range(len(new_cipher_list)):
                cipher += self.binary_list_to_char(new_cipher_list[i])
            return cipher
        elif self.key_length == 192:
            k1 = key_list[0]
            k1.extend(key_list[1])
            k1.extend(key_list[2])
            k1.extend(key_list[3])
            key_transform = self.xor_lists(first_bit_list,k1 )
            for i in range(1,13):
                s_sub_list = self.s_sub(key_transform)
                shifted_matrix= self.shift_row(s_sub_list)
                col_shift_matrix = self.mix_columns(shifted_matrix)
                diffusion_list = self.join_list(col_shift_matrix)
                k1 = key_list[(4*i)+0]
                k1.extend(key_list[(4*i)+1])
                k1.extend(key_list[(4*i)+2])
                k1.extend(key_list[(4*i)+3])
                key_transform = self.xor_lists(diffusion_list,k1 )
            new_cipher_list = self.divide_chunks(key_transform,8)
            cipher = ""
            for i in range(len(new_cipher_list)):
                cipher += self.binary_list_to_char(new_cipher_list[i])
            return cipher
        else:
            k1 = key_list[0]
            k1.extend(key_list[1])
            k1.extend(key_list[2])
            k1.extend(key_list[3])
            key_transform = self.xor_lists(first_bit_list,k1 )
            for i in range(1,15):
                s_sub_list = self.s_sub(key_transform)
                shifted_matrix= self.shift_row(s_sub_list)
                col_shift_matrix = self.mix_columns(shifted_matrix)
                diffusion_list = self.join_list(col_shift_matrix)
                k1 = key_list[(4*i)+0]
                k1.extend(key_list[(4*i)+1])
                k1.extend(key_list[(4*i)+2])
                k1.extend(key_list[(4*i)+3])
                key_transform = self.xor_lists(diffusion_list,k1 )
            new_cipher_list = self.divide_chunks(key_transform,8)
            cipher = ""
            for i in range(len(new_cipher_list)):
                cipher += self.binary_list_to_char(new_cipher_list[i])
            return cipher

    
    def binary_list_to_char(self, binary_list):
        # Convert the binary list to a binary string
        binary_str = ''.join(str(bit) for bit in binary_list)
        
        # Convert the binary string to an integer
        integer = int(binary_str, 2)
        
        # Convert the integer to a character
        character = chr(integer)
        
        return character
    #-------------------------------x--------------------------------- sub byte
    def s_sub(self,bit_list):
        s_box_match = [['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'], 
                       ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'FO', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'CO'], 
                       ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'], 
                       ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'], 
                       ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
                         ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'], 
                         ['DO', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'], 
                         ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'], 
                         ['CD', '0C', '3', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'], 
                         ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', 'OB', 'DB'], 
                         ['EO', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'], 
                         ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'], 
                         ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'], 
                         ['70', '3E', 'B5', '66', '48', '03', 'F6', 'OE', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'], 
                         ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'], 
                         ['8C', 'A1', '89', 'OD', 'BF', 'E6', '42', '68', '41', '99', '2D', 'OF', 'BO', '54', 'BB', '16']]
        new_s_sub_list = []
        for i in range(len(bit_list)):
            row_bin = ''.join(bit_list[i][:4])
            row_val = int(row_bin,2)
            col_bin = ''.join(bit_list[i][4:])
            col_val = int(col_bin,2)
            new_s_val = s_box_match[row_val][col_val]
            new_bit_list = self.val_to_bitlist(new_s_val[0],new_s_val[1])
            new_s_sub_list.append(new_bit_list)

        return new_s_sub_list
    
    def val_to_bitlist(self,first_dig, second_dig):
        ascii_f = ord(first_dig)
        ascii_s = ord(second_dig)
        bin_f = bin(ascii_f)[2:]
        bin_s = bin(ascii_s)[2:]
        bin_f_list = [int(bit) for bit in bin_f[-4:]]
        bin_s_list = [int(bit) for bit in bin_s[-4:]]
        new_list = bin_f_list.extend(bin_s_list)
        return new_list
    #------------------------------x---------------------------------- shift row
    def transpose_matrix(self,matrix):
    # Transposes a matrix, rotating it by 90 degrees clockwise.
        rows = len(matrix)
        cols = len(matrix[0])
        transposed_matrix = [[None for _ in range(rows)] for _ in range(cols)]
        for i in range(rows):
            for j in range(cols):
                transposed_matrix[j][rows - i - 1] = matrix[i][j]
        return transposed_matrix

    def shift_row(self,input_matrix):
        func = Functions()
        submatrx = []
        updated_sub_matrx = self.group_lists_into_sublists(submatrx,input_matrix,4 )
        new_input_matrix = self.transpose_matrix(updated_sub_matrx)
        updated_matrix = []
        for i in range(len(new_input_matrix)):
            updated_matrix.append(func.rotate(new_input_matrix[i],i))
        return updated_matrix
    
    def group_lists_into_sublists(self,new_list, list_of_lists, group_size):
        for i in range(0, len(list_of_lists), group_size):
            new_list.append(list_of_lists[i:i+group_size])
        return new_list
    
    #-------------------------------x--------------------------- mix col

    def binary_list_to_int(self,binary_list):
        return int(''.join(str(bit) for bit in binary_list), 2)

    def int_to_binary_list(self,value):
        return [int(bit) for bit in format(value, '08b')]

    def galois_multiplication(self,a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a <<= 1
            if high_bit_set:
                a ^= 0x1B  # AES reduction polynomial
            b >>= 1
        return p & 0xFF

    def mix_columns(self,state):
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            new_state[0][c] = self.galois_multiplication(0x02, state[0][c]) ^ self.galois_multiplication(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
            new_state[1][c] = state[0][c] ^ self.galois_multiplication(0x02, state[1][c]) ^ self.galois_multiplication(0x03, state[2][c]) ^ state[3][c]
            new_state[2][c] = state[0][c] ^ state[1][c] ^ self.galois_multiplication(0x02, state[2][c]) ^ self.galois_multiplication(0x03, state[3][c])
            new_state[3][c] = self.galois_multiplication(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ self.galois_multiplication(0x02, state[3][c])
        return new_state

    #------------------------------------x-------------------------- join all lists together
    def join_list(self,list_o_lists):
        new_list = [val for i in list_o_lists for j in list_o_lists[i] for val in list_o_lists[i][j]]
        return new_list


    #--------------------------------x--------------------------------key schedule
    def key_schedule_list(self):
        func = Functions()
        input_key_list = func.words_to_bits(self.key)
        first_round = self.init_round(input_key_list)
        w = []
        for i in range(len(first_round)):
            w.append(first_round[i])
        if self.key_length == 128:
            for i in range(10):
                sub_w = w[-4:]
                g_convert = self.g_function(sub_w[-1],i)
                new_word_1 = self.xor_lists(sub_w[0], g_convert)
                w.append(new_word_1)
                new_word_2 = self.xor_lists(new_word_1, sub_w[1])
                w.append(new_word_2)
                new_word_3 = self.xor_lists(new_word_2, sub_w[2])
                w.append(new_word_3)
                new_word_4 = self.xor_lists(new_word_3, sub_w[3])
                w.append(new_word_4)
        elif self.key_length == 192:
            for i in range(12):
                sub_w = w[-6:]
                g_convert = self.g_function(sub_w[-1],i)
                new_word_1 = self.xor_lists(sub_w[0], g_convert)
                w.append(new_word_1)
                new_word_2 = self.xor_lists(new_word_1, sub_w[1])
                w.append(new_word_2)
                new_word_3 = self.xor_lists(new_word_2, sub_w[2])
                w.append(new_word_3)
                new_word_4 = self.xor_lists(new_word_3, sub_w[3])
                w.append(new_word_4)
                new_word_5 = self.xor_lists(new_word_4, sub_w[4])
                w.append(new_word_5)
                new_word_6 = self.xor_lists(new_word_5, sub_w[5])
                w.append(new_word_6)         
        else:
            for i in range(14):
                sub_w = w[-8:]
                g_convert = self.g_function(sub_w[-1],i)
                new_word_1 = self.xor_lists(sub_w[0], g_convert)
                w.append(new_word_1)
                new_word_2 = self.xor_lists(new_word_1, sub_w[1])
                w.append(new_word_2)
                new_word_3 = self.xor_lists(new_word_2, sub_w[2])
                w.append(new_word_3)
                new_word_4 = self.xor_lists(new_word_3, sub_w[3])
                w.append(new_word_4)
                new_word_5 = self.xor_lists(new_word_4, sub_w[4])
                w.append(new_word_5)
                new_word_6 = self.xor_lists(new_word_5, sub_w[5])
                w.append(new_word_6)
                new_word_7 = self.xor_lists(new_word_6, sub_w[6])
                w.append(new_word_7)
                new_word_8 = self.xor_lists(new_word_7, sub_w[7])
                w.append(new_word_8)
        return w

    def xor_lists(self,list1,list2):
        new_list = []
        for i in range(len(list1)):
            val = list1[i] ^ list2[i]
            new_list.append(val)
        return new_list

#---------------------x----------------------- first round
    def init_round(self,matrix):
        j_matrix = [val for i in range(len(matrix)) for val in range(len(matrix[i]))]
        init_key_list = self.divide_chunks(j_matrix,32)
        return init_key_list
    
    def divide_chunks(self, l, n):
        # Initialize an empty list to store the chunks
        chunks = []
        
        # Looping till length of l
        for i in range(0, len(l), n):
            # Append each chunk to the chunks list
            chunks.append(l[i:i + n])
        
        # Return the list of chunks
        return chunks


#----------------x----------------------g function

    def g_function(self,bit_list,round):
        func = Functions()
        new_bit_list = self.divide_chunks(bit_list,8)
        shifted_list = func.rotate(new_bit_list,1)
        rc_val = [ "00000001","00000010","00000100", "00001000","00010000",
    "00100000","01000000","10000000","00011011","00110110", "01101100",
    "11011000","10101011","01001101","10011110","00110111", "01101110",
    "11011100","10100011","01000001","10000010","00111111", "01111110",
    "11111100","11101111","11000101","10010001","00100111", "01001110",
    "10011100","00111000",]
        shifted_element = []
        for i in range(len(rc_val[round])):
            new_val = rc_val[round][i] ^ shifted_list[0][i]
            shifted_element.append(new_val)

        shifted_list[0] = shifted_element
        final_g_list = list(itertools.chain.from_iterable(shifted_list))
        return final_g_list

class Modern:
    def __init__(self):
        inp = self.get_user_input()

    def get_user_input(self):
        print("Which encryption would you prfer:")
        print("1) Default Encryption Standard")
        print("2) 3 (Default Encryption Standard) or 3DES")
        print("3) Advanced Encryption Standard")
        while True:
            inp =  input("Enter your choice (1,2,3): ")
            print("\n")
            if inp == "1":
                return self.main_input_des()
            if inp == "2":
                return self.three_des()
            if inp == "3":
                return self.main_input_aes()
            else:
                print("Invalid Input \n")
                x = input("Enter only either these choices (1,2,3): ")
                print("\n")
# ----------------------------x --------------------- DES ENCRYPTION
# ask for input and key seperately
    #4
    def des_encryption(self,word,key_s):
        des_encrypt = DES_Cipher_Encryption(p_input=word)
        # ask for different modes of encryption 
        des_encrypt.key = key_s
        cipher_t = des_encrypt.encrypt()
        return cipher_t
    #1
    def main_input_des(self):
        func = Functions()
        msg = func.getmsg()
        if len(msg) > 8:
            string_mode_op = self.mode_operation(msg,8, "DES")
            return string_mode_op
        elif len(msg) == 8:
            # get key 
            key = self.getkey_des()
            # perform encryption
            cipher = self.des_encryption(msg,key)
            # produce cipher
            return cipher
        else:
            while len(msg) < 8:
                msg = msg + " "
            # get key 
            key = self.getkey_des()
            # perform encryption
            cipher = self.des_encryption(msg,key)
            # produce cipher
            return cipher
    
    def generate_random_n_bit_list(self,n):
        return [random.randint(0, 1) for _ in range(n)]
    #2
    def getkey_des(self):
        func = Functions()
        key = input("Provide the key for encryption with a string or strings of alphabets that matches a total of 64-bit length: ")
        print("\n")
        while not func.is_valid_input(key):
            key = input("Provide valid key (string of alphabets) for encryption that matches a total of 64-bit length: ")
            print("\n")
        else:
            if not key:
                new_key = [random.choice(string.ascii_letters) for _ in range(8)]
                new_key = ''.join(new_key)
                print("Generating default key: ", new_key)
                return new_key
            elif len(key) > 8:
                print("Shortening provided key to required amount: ", key[:8])
                print("\n")
                return key[:8]
            elif len(key) == 8:
                return key
            else:
                while len(key) < 8:
                    print("Extra space added to meet required amout of 64 bit.")
                    print("\n")
                    key = key + " "
                return key
            
#-------------------------------------X---------------------------------------- MOD OPERATION
    def check_char_miss_char(self,list1):
        if len(list1[-1]) < 8:
            while len(list1[-1]) < 8:
                list1[-1] = list1[-1] + " "
            else:
                return list1
        else:
            return list1


    def mode_operation(self,word,chunks,algo):
        aes_func= AES_Cipher_Encryption()
        func = Functions()
        print("Given the provided block of text is bigger than the base amount, which mode of encryption would you prefer to be used? ")
        print("1) Electronic CodeBook")
        print("2) Cipher Block Chaining Mode")
        print("3) Counter Mode")
        inp =  input("Enter your choice (1,2,3): ")
        print("\n")
            #3---------------------------X-------------------------------------  DES MODE
           
        if algo == "DES":
             # ECB MODE
            if inp == "1":
                string_list = aes_func.divide_chunks(word,chunks)
                checked_string_list = self.check_char_miss_char(string_list)
                key = self.getkey_des()
                cipher_list = []
                for i in range(len(checked_string_list)):
                    cipher_list.append(self.des_encryption(checked_string_list[i],key))
                cipher = list(itertools.chain.from_iterable(cipher_list))
                cipher= ''.join(cipher)
                return cipher
                # CBC mode
            if inp == "2":
                # divide into char blocks
                string_list = aes_func.divide_chunks(word,chunks)
                # check last element is 8 bytes
                checked_string_list = self.check_char_miss_char(string_list)
                # get key
                key = self.getkey_des()
                cipher_list = []
                # create the IV value 
                iv_gen =self.generate_random_n_bit_list(32)
                # take the first element of the plaintext blocks and get each 8-bit values
                init_round = func.words_to_bits(checked_string_list[0])
                # combine them to form 64-bit
                init_round_list = list(itertools.chain.from_iterable(init_round))
                # xor as given in logic
                iv_applied_element = aes_func.xor_lists(init_round_list,iv_gen )
                # divide the chunks
                new_char_list = aes_func.divide_chunks(iv_applied_element,8)
                # creates the first cipher block
                first_char = ""
                for j in range(len(new_char_list)):
                    first_char += aes_func.binary_list_to_char(new_char_list[j])
                # perform the encryption
                first_cipher_element = self.des_encryption(first_char,key)
                # add it to the cipher list
                cipher_list.append(first_cipher_element)
                for k in range(1,len(checked_string_list)):
                    main_round = func.words_to_bits(checked_string_list[k])
                     # combine them to form 64-bit
                    main_round_list = list(itertools.chain.from_iterable(main_round))
                    previous_round = func.words_to_bits(cipher_list[-1])
                     # combine them to form 64-bit
                    previous_round_list = list(itertools.chain.from_iterable(previous_round))
                    # xor as given in logic
                    xor_applied_element = aes_func.xor_lists(main_round_list,previous_round_list)
                    new_char_list = aes_func.divide_chunks(xor_applied_element,8)
                    # creates the cipher block
                    first_char = ""
                    for j in range(len(new_char_list)):
                        first_char += aes_func.binary_list_to_char(new_char_list[j])
                    # perform the encryption
                    first_cipher_element = self.des_encryption(first_char,key)
                    # add it to the cipher list
                    cipher_list.append(first_cipher_element)
                
                # combine blocks together
                cipher = ''.join(cipher_list)
                return cipher      
                # CTRL mode
            if inp == "3":
                # divide into char blocks
                string_list = aes_func.divide_chunks(word,chunks)
                # check last element is 8 bytes
                checked_string_list = self.check_char_miss_char(string_list)
                # get key
                key = self.getkey_des()
                cipher_list = []
                # create the IV value 
                iv_gen =self.generate_random_n_bit_list(32)
                # create a counter
                counter = Counter(32)
                for i in range(len(checked_string_list)):
                    new_counter = []
                    if i == 0:
                        new_counter.append(iv_gen.extend(counter.counter))
                    else:
                        new_counter.append(iv_gen.extend(counter.increment()))
                    # divide the chunks
                    new_char_list = aes_func.divide_chunks(new_counter,8)
                    # creates the first cipher block
                    first_char = ""
                    for j in range(len(new_char_list)):
                        first_char += aes_func.binary_list_to_char(new_char_list[j])
                    # run through encryption
                    ctr_encrypt = self.des_encryption(first_char, key)
                    # create the bit list
                    ctr_encrypt_list = func.words_to_bits(ctr_encrypt)
                    # join to create 64 bits
                    ctr_encrypt_bit_list = list(itertools.chain.from_iterable(ctr_encrypt_list))
                    # create the plain block list
                    ctr_plain_list = func.words_to_bits(checked_string_list[i])
                    # join to create 64 bits
                    ctr_plain_bloc_list = list(itertools.chain.from_iterable(ctr_plain_list))
                    # xor as given in logic
                    xor_applied_element = aes_func.xor_lists(ctr_encrypt_bit_list,ctr_plain_bloc_list)
                    new_char_list = aes_func.divide_chunks(xor_applied_element,8)
                    # creates the xor block
                    first_block = ""
                    for j in range(len(new_char_list)):
                        first_block += aes_func.binary_list_to_char(new_char_list[j])
                    # add it to the cipher list
                    cipher_list.append(first_block)

                # combine blocks together
                cipher = ''.join(cipher_list)
                return cipher  
#x----------------------------------------X-------------------------------- AES LOGIC MODE
            else:
                print("Invalid Input \n")
                x = input("Enter only either these choices (1,2,3): ")
                print("\n")
        else:
            # ECB mode
            if inp == "1":
                string_list = aes_func.divide_chunks(word,chunks)
                checked_string_list = self.check_char_miss_char(string_list)
                key,key_length1 = self.getkey_aes()
                cipher_list = []
                for i in range(len(checked_string_list)):
                    cipher_list.append(self.aes_encryption(checked_string_list[i],key,key_length1))
                cipher = list(itertools.chain.from_iterable(cipher_list))
                cipher= ''.join(cipher)
                return cipher
                # CBC mode
            if inp == "2":
                string_list = aes_func.divide_chunks(word,chunks)
                checked_string_list = self.check_char_miss_char(string_list)
                key,key_length1 = self.getkey_aes()
                cipher_list = []
                #------------------x--------------------
                # create the IV value 
                iv_gen =self.generate_random_n_bit_list(64)
                # take the first element of the plaintext blocks and get each 8-bit values
                init_round = func.words_to_bits(checked_string_list[0])
                # combine them to form 64-bit
                init_round_list = list(itertools.chain.from_iterable(init_round))
                # xor as given in logic
                iv_applied_element = aes_func.xor_lists(init_round_list,iv_gen )
                # divide the chunks
                new_char_list = aes_func.divide_chunks(iv_applied_element,8)
                # creates the first cipher block
                first_char = ""
                for j in range(len(new_char_list)):
                    first_char += aes_func.binary_list_to_char(new_char_list[j])
                # perform the encryption------------------------- aes
                first_cipher_element = self.aes_encryption(first_char,key, key_length1)
                # add it to the cipher list
                cipher_list.append(first_cipher_element)
                for k in range(1,len(checked_string_list)):
                    main_round = func.words_to_bits(checked_string_list[k])
                     # combine them to form 64-bit
                    main_round_list = list(itertools.chain.from_iterable(main_round))
                    previous_round = func.words_to_bits(cipher_list[-1])
                     # combine them to form 64-bit
                    previous_round_list = list(itertools.chain.from_iterable(previous_round))
                    # xor as given in logic
                    xor_applied_element = aes_func.xor_lists(main_round_list,previous_round_list)
                    new_char_list = aes_func.divide_chunks(xor_applied_element,8)
                    # creates the cipher block
                    first_char = ""
                    for j in range(len(new_char_list)):
                        first_char += aes_func.binary_list_to_char(new_char_list[j])
                    # perform the encryption
                    first_cipher_element = self.aes_encryption(first_char,key,key_length1)
                    # add it to the cipher list
                    cipher_list.append(first_cipher_element)
                
                # combine blocks together
                cipher = ''.join(cipher_list)
                return cipher 
                
                # CTRL mode
            if inp == "3":
                string_list = aes_func.divide_chunks(word,chunks)
                checked_string_list = self.check_char_miss_char(string_list)
                key,key_length1 = self.getkey_aes()
                cipher_list = []
                #------------------x--------------------

            else:
                print("Invalid Input \n")
                x = input("Enter only either these choices (1,2,3): ")
                print("\n")
        return 
#----------------------X-------------------------------------- 3DES

    def three_des(self):
        return
# checck if key length valid and check if it matches key length 
# check modes of operation
    def aes(self):
        func = Functions()
        plaintext = func.getmsg()
        # modes of encryption needed

        return
# ---------------------------------------X------------------------------- AES ENCRYPTION
    def main_input_aes(self):
        func = Functions()
        msg = func.getmsg()
        if len(msg) > 16:
            string_mode_op = self.mode_operation(msg,8, "AES")
            return string_mode_op
        elif len(msg) == 16:
            # get key 
            key,key_len = self.getkey_aes()
            # perform encryption
            cipher = self.aes_encryption(msg,key, key_len)
            # produce cipher
            return cipher
        else:
            while len(msg) < 16:
                msg = msg + " "
            # get key 
            key,key_len = self.getkey_aes()
            # perform encryption
            cipher = self.aes_encryption(msg,key, key_len)
            # produce cipher
            return cipher
        
    def aes_encryption(self,word,key_s,key_len):
        aes_encrypt = AES_Cipher_Encryption(p_input=word)
        # ask for different modes of encryption 
        aes_encrypt.key = key_s
        aes_encrypt.key_length = key_len
        cipher_t = aes_encrypt.encrypt()
        return cipher_t
    # ---------------------------------------X------------------------------- AES key
    def getkey_aes(self):
        func = Functions()
        key_len = input("Provide the length of the key for encryption with a string or strings of alphabets that matches a 128-bit, 192-bit or 256-bit key: ")
        print("\n")
        while key_len != 128 or key_len != 192 or key_len != 256:
            key = input("Provide valid key length for encryption that matches a 128-bit, 192-bit or 256-bit key: ")
            print("\n")
        key = input("Provide the key for encryption with a string or strings of alphabets that matches a 128-bit, 192-bit or 256-bit key: ")
        print("\n")
        while not func.is_valid_input(key):
            key = input("Provide valid key (string of alphabets) for encryption that matches a 128-bit, 192-bit or 256-bit key: ")
            print("\n")
        else:
            key_prepared = self.key_verification_func(key,key_len)
            return key_prepared, key_len
            
    def key_verification_func(self,key_main,key_length):
        if not key_main:
                new_key = [random.choice(string.ascii_letters) for _ in range(key_length)]
                new_key = ''.join(new_key)
                print("Generating default key: ", new_key)
                return new_key
        elif len(key_main) > key_length:
                print("Shortening provided key to required amount: ", key_main[:key_length])
                print("\n")
                return key_main[:key_length]
        elif len(key_main) == key_length:
                return key_main
        else:
                while len(key_main) < key_length:
                    print("Extra space added to meet required amout of 64 bit.")
                    print("\n")
                    key_main = key_main + " "
                return key_main

#-----------------------------------------X---------------------------------
class Counter:
    def __init__(self,n):
        self.counter = [0]*n
    
    def increment(self):
        # Convert the counter list to an integer
        counter_value = int(''.join(map(str, self.counter)), 2)
        
        # Check if the counter exceeds the 64-bit limit
        if counter_value > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("Counter has exceeded the 64-bit limit")
        
        # Increment the counter value
        counter_value += 1
        
        # Convert the incremented counter value back to a list of 64 bits
        new_counter = format(counter_value, '064b')
        self.counter = [int(bit) for bit in new_counter]
        
        return self.counter
