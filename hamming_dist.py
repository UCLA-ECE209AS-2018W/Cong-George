import pickle
import os
import sys
from device_signature import *
import signature_database_create as sdc

class hexed_wifi_sig:
	def __init__(self, sig_type):
		self.type = sig_type
		self.probe_id = ''
		self.htcap = ''
		self.httag = ''
		self.htmcs = ''
		self.vhtcap = ''
		self.vhtrxmcs = ''
		self.vhttxmcs = ''
		self.extcap = ''
		self.txpow = ''
		self.excap = ''

	def display(self):
		print('probe_id: ' + str(self.probe_id))
		print('htcap: ' + xstr(self.htcap))
		print('httag: ' + xstr(self.httag))
		print('htmcs: ' + xstr(self.htmcs))
		print('vhtcap: ' + xstr(self.vhtcap))
		print('vhtrxmcs: ' + xstr(self.vhtrxmcs))
		print('vhttxmcs: ' + xstr(self.vhttxmcs))
		print('extcap: ' + xstr(self.extcap))
		print('txpow: ' + xstr(self.txpow))
		print('excap: ' + xstr(self.excap))

def xstr(str_in):
	return '' if str_in is None else str(str_in)
'''
Input:  
wifi_sig signature to be classified

Return: 
a hexed_wifi_sig class list that contains all information in all signatures in hex form

Note: 
1.Correct information has to be import to input before calling this functiuon!!!

2.A single stacked_wifi_sig may contains multiuple signatures corresponding to asso and probe

'''

def parse_stacked_sigs(input_wifi_sig):
	ret_hexed_list = []
	if input_wifi_sig.has_probe == 1:
		print('Probe requested!')
		hexed_probe_sig = hexed_wifi_sig('probe')
		
		#probe id
		hexed_probe_sig.probe_id = input_wifi_sig.probe_sig.probe_id
		#htcap
		hexed_probe_sig.htcap = str_to_hex(input_wifi_sig.probe_sig.htcap)
		#httag
		hexed_probe_sig.httag = str_to_hex(input_wifi_sig.probe_sig.httag)
		#htmcs
		hexed_probe_sig.htmcs = str_to_hex(input_wifi_sig.probe_sig.htmcs)
		#vhtcap
		hexed_probe_sig.vhtcap = str_to_hex(input_wifi_sig.probe_sig.vhtcap)
		#vhtrxmcs
		hexed_probe_sig.vhtrxmcs = str_to_hex(input_wifi_sig.probe_sig.vhtrxmcs)
		#vhttxmcs
		hexed_probe_sig.vhttxmcs = str_to_hex(input_wifi_sig.probe_sig.vhttxmcs)
		#extcap
		hexed_probe_sig.extcap = str_to_hex(input_wifi_sig.probe_sig.extcap)
		#txpow
		hexed_probe_sig.txpow = str_to_hex(input_wifi_sig.probe_sig.txpow)
		#excap
		hexed_probe_sig.excap = str_to_hex(input_wifi_sig.probe_sig.excap)

		ret_hexed_list.append(hexed_probe_sig)

	
	#asso information converting & filling
	if input_wifi_sig.has_ass == 1:
		print('Asso requested!')
		hexed_ass_sig = hexed_wifi_sig('asso')
		#probe id
		hexed_ass_sig.probe_id = input_wifi_sig.ass_sig.probe_id
		#htcap
		hexed_ass_sig.htcap = str_to_hex(input_wifi_sig.ass_sig.htcap)
		#httag
		hexed_ass_sig.httag = str_to_hex(input_wifi_sig.ass_sig.httag)
		#htmcs
		hexed_ass_sig.htmcs = str_to_hex(input_wifi_sig.ass_sig.htmcs)
		#vhtcap
		hexed_ass_sig.vhtcap = str_to_hex(input_wifi_sig.ass_sig.vhtcap)
		#vhtrxmcs
		hexed_ass_sig.vhtrxmcs = str_to_hex(input_wifi_sig.ass_sig.vhtrxmcs)
		#vhttxmcs
		hexed_ass_sig.vhttxmcs = str_to_hex(input_wifi_sig.ass_sig.vhttxmcs)
		#extcap
		hexed_ass_sig.extcap = str_to_hex(input_wifi_sig.ass_sig.extcap)
		#txpow
		hexed_ass_sig.txpow = str_to_hex(input_wifi_sig.ass_sig.txpow)
		#excap
		hexed_ass_sig.excap = str_to_hex(input_wifi_sig.ass_sig.excap)

		ret_hexed_list.append(hexed_ass_sig)

	return ret_hexed_list


'''
Input: Possible non-empty signature contains info in raw hex format

Output: String contains ':' seperated info in byte

'''
def str_to_hex(input_str):
	if input_str != '':
		byte_string = ':'.join('{:02x}'.format(ord(c)) for c in input_str)
		return byte_string


'''
Input: wifi_sig to be compare with certain database

Output: the signature with least difference.

Iterating through every signature class in class wifi_sig 
'''

def get_diff(database, captured_wifi_sig):

	#preprocess captured_wifi_sig -> hex asso sig + hex probe sig
	hexed_captured_wifi_sig_list = parse_stacked_sigs(captured_wifi_sig)
	if hexed_captured_wifi_sig_list[0].type == 'asso':
		captured_hexed_asso_sig = hexed_captured_wifi_sig_list[0]
		captured_hexed_probe_sig = hexed_captured_wifi_sig_list[1]
	else:
		captured_hexed_asso_sig = hexed_captured_wifi_sig_list[1]
		captured_hexed_probe_sig = hexed_captured_wifi_sig_list[0]


	#score[x] is probe hamming dist+asso hamming dist
	score = []
	#list1 is the list that contains hexed sigs of different devices
	for list_1 in database:
		print(str(len(list_1)) + ' hexed signatures to be compared with!')
		
		#computing hamming dist
		for sig in list_1:
			probe_score = 0
			asso_score = 0

			#prove vs. probe
			if sig.type == 'probe':
				probe_score += get_hamming_dist(str(sig.probe_id), str(captured_hexed_probe_sig.probe_id))
				print('htcap')
				probe_score += get_hamming_dist(sig.htcap, captured_hexed_probe_sig.htcap)
				print('httag')
				probe_score += get_hamming_dist(sig.httag, captured_hexed_probe_sig.httag)
				print('htmcs')
				probe_score += get_hamming_dist(sig.htmcs, captured_hexed_probe_sig.htmcs)
				print('vhtcap')
				probe_score += get_hamming_dist(sig.vhtcap, captured_hexed_probe_sig.vhtcap)
				print('vhtrxmcs')
				probe_score += get_hamming_dist(sig.vhtrxmcs, captured_hexed_probe_sig.vhtrxmcs)
				print('vhttxmcs')
				probe_score += get_hamming_dist(sig.vhttxmcs, captured_hexed_probe_sig.vhttxmcs)
				print('extcap')
				probe_score += get_hamming_dist(sig.extcap, captured_hexed_probe_sig.extcap)
				print('txpow')
				probe_score += get_hamming_dist(sig.txpow, captured_hexed_probe_sig.txpow)
				print('excap')
				probe_score += get_hamming_dist(sig.excap, captured_hexed_probe_sig.excap)
				print('probe score:' + str(probe_score))
			
			#asso vs. asso
			else:
				asso_score += get_hamming_dist(str(sig.probe_id), str(captured_hexed_asso_sig.probe_id))
				print('htcap')
				asso_score += get_hamming_dist(sig.htcap, captured_hexed_asso_sig.htcap)
				print('httag')
				asso_score += get_hamming_dist(sig.httag, captured_hexed_asso_sig.httag)
				print('htmcs')
				asso_score += get_hamming_dist(sig.htmcs, captured_hexed_asso_sig.htmcs)
				print('vhtcap')
				asso_score += get_hamming_dist(sig.vhtcap, captured_hexed_asso_sig.vhtcap)
				print('vhtrxmcs')
				asso_score += get_hamming_dist(sig.vhtrxmcs, captured_hexed_asso_sig.vhtrxmcs)
				print('vhttxmcs')
				asso_score += get_hamming_dist(sig.vhttxmcs, captured_hexed_asso_sig.vhttxmcs)
				print('extcap')
				asso_score += get_hamming_dist(sig.extcap, captured_hexed_asso_sig.extcap)
				print('txpow')
				asso_score += get_hamming_dist(sig.txpow, captured_hexed_asso_sig.txpow)
				print('excap')
				asso_score += get_hamming_dist(sig.excap, captured_hexed_asso_sig.excap)
				print('asso score:' + str(asso_score))
		score.append(probe_score + asso_score)



def get_hamming_dist(str1, str2):
	str1 = xstr(str1)
	str2 = xstr(str2)
	print('comparing: ' + str1 + ' ||| ' + str2)
	if str1 == '' and str2 == '':
		return 0
	elif str1 == '' and str2 != '':
		return len(str2)
	elif str1 !='' and str2 == '':
		return len(str1)
	elif len(str1) == len(str2):
		diff = 0
		for ch1, ch2 in zip(str1, str2):
			if ch1 != ch2:
				diff+=1
		return diff
	else:
		print('Invalid comparison!')


'''
Input: 
dir of file that contains the databse

Output: 
1.a list of hexed formed signatures as new database.
2.This list is a list of list

'''

def load_hex_database(database_file):
	ret_list = []
	if os.path.exists(database_file):
		with open(database_file, 'rb') as data:
			database = pickle.load(data)
		print(str(len(database.items())) + ' stacked wifi_sig in the database!')
		for device_name, stacked_signature in database.items():
			print('device name: ' + device_name)
			hexed_wifi_list = parse_stacked_sigs(stacked_signature[1])
			print(str(len(hexed_wifi_list)) + ' signatures detected in this wifi_sig class!')
			for item in hexed_wifi_list:
				print('Type: ' + item.type)
				item.display()
			ret_list.append(hexed_wifi_list)

	return ret_list




if __name__ == "__main__":
	#speficify database_file here after comprehensive data to it
	database_file = "signature_database.p"
	hexed_database = load_hex_database(database_file)
	get_diff(hexed_database, test_wifi_sig)








