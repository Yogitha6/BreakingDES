###########################################################
#	    Differential Cryptanalysis Attack on 3 round DES	  #
#	              Yogitha Mahadasu                          #
###########################################################

import itertools

sboxTable1 = []
sboxTable2 = []
sboxTable3 = []
sboxTable4 = []
sboxTable5 = []
sboxTable6 = []
sboxTable7 = []
sboxTable8 = []
table1 = {}
table2 = {}
table3 = {}
table4 = {}
table5 = {}
table6 = {}
table7 = {}
table8 = {}

pc1 = [57, 49, 41, 33, 25, 17,  9,   1, 58, 50, 42, 34, 26, 18,
       10,  2, 59, 51, 43, 35, 27,  19, 11,  3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,   7, 62, 54, 46, 38, 30, 22,
       14,  6, 61, 53, 45, 37, 29,  21, 13,  5, 28, 20, 12,  4]

pc2 = [14, 17, 11, 24,  1,  5,       3, 28, 15,  6, 21, 10,
       23, 19, 12,  4, 26,  8,      16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55,      30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,      46, 42, 50, 36, 29, 32]

p = [16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25]

expansionFunction = [
	     32,  1,  2,  3,  4,  5,
              4,  5,  6,  7,  8,  9,
	      8,  9, 10, 11, 12, 13,
	     12, 13, 14, 15, 16, 17,
	     16, 17, 18, 19, 20, 21,
	     20, 21, 22, 23, 24, 25,
	     24, 25, 26, 27, 28, 29,
	     28, 29, 30, 31, 32,  1]

#Defining the S-boxes - the heart of DES
def constructSboxes():	
	sbox1 = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
	i = 0
	for j in xrange(4):
		sboxTable1.append([])
		for k in xrange(16):
			sboxTable1[j].append(sbox1[i])
			i = i +1

	sbox2 = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
	i = 0
	for j in xrange(4):
		sboxTable2.append([])
		for k in xrange(16):
			sboxTable2[j].append(sbox2[i])
			i = i +1


	sbox3 = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 ]
	i = 0
	for j in xrange(4):
		sboxTable3.append([])
		for k in xrange(16):
			sboxTable3[j].append(sbox3[i])
			i = i +1


	sbox4 = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4, 
	   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
	i = 0
	for j in xrange(4):
		sboxTable4.append([])
		for k in xrange(16):
			sboxTable4[j].append(sbox4[i])
			i = i +1

	sbox5 = [2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 ]
	i = 0
	for j in xrange(4):
		sboxTable5.append([])
		for k in xrange(16):
			sboxTable5[j].append(sbox5[i])
			i = i +1

	sbox6 = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
	i = 0
	for j in xrange(4):
		sboxTable6.append([])
		for k in xrange(16):
			sboxTable6[j].append(sbox6[i])
			i = i +1

	sbox7 = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
	i = 0
	for j in xrange(4):
		sboxTable7.append([])
		for k in xrange(16):
			sboxTable7[j].append(sbox7[i])
			i = i +1

	sbox8 = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 ]
	i = 0
	for j in xrange(4):
		sboxTable8.append([])
		for k in xrange(16):
			sboxTable8[j].append(sbox8[i])
			i = i +1

#method to convert binary to decimal
def decimal(binaryList):
	decimalValue = 0
	place = 0
	for digit in reversed(binaryList):
		if(digit!=None):
			decimalValue = decimalValue + digit * pow(2,place)
			place = place + 1
	return decimalValue

#method to convert demical to binary
def binary(decimalVal):
	binaryValue = []
	i = 0
	if(decimalVal < 16):
		while(i < 4):
			remainder = decimalVal % 2
			binaryValue.append(remainder)
			decimalVal = decimalVal / 2
			i = i + 1
	else:
		while(i < 32):
			remainder = decimalVal % 2
			binaryValue.append(remainder)
			decimalVal = decimalVal / 2
			i = i + 1
	binaryValue.reverse()
	return binaryValue

#method to construct the tally realizaiton tables for the deltaBj - inputXOR value
def constructMapTables(deltaBj):
	for i in xrange(1,9):
		outputXors = list(itertools.product([0,1], repeat = 4))
		allpossibleBjvalues = list(itertools.product([0,1], repeat = 6))
		for value in outputXors:
			if(i == 1):
				table1[value] = []
			elif (i==2):
				table2[value] = []
			elif (i==3):
				table3[value] = []
			elif (i==4):
				table4[value] = []
			elif (i==5):
				table5[value] = []
			elif (i==6):
				table6[value] = []
			elif (i==7):
				table7[value] = []
			elif (i==8):
				table8[value] = []	
		for bj1value in allpossibleBjvalues:
			bj2value = xor(bj1value,deltaBj)
			output1 = sbox(bj1value,i)
			output2 = sbox(bj2value,i)
			outputxor = xor(binary(output1),binary(output2))
			if(i == 1):
				if(bj2value not in table1[tuple(outputxor)]):
					table1[tuple(outputxor)].append(bj2value)
			elif (i==2):
				if(bj2value not in table2[tuple(outputxor)]):
					table2[tuple(outputxor)].append(bj2value)
			elif (i==3):
				if(bj2value not in table3[tuple(outputxor)]):					
					table3[tuple(outputxor)].append(bj2value)
			elif (i==4):
				if(bj2value not in table4[tuple(outputxor)]):
					table4[tuple(outputxor)].append(bj2value)
			elif (i==5):
				if(bj2value not in table5[tuple(outputxor)]):
					table5[tuple(outputxor)].append(bj2value)
			elif (i==6):
				if(bj2value not in table6[tuple(outputxor)]):
					table6[tuple(outputxor)].append(bj2value)
			elif (i==7):
				if(bj2value not in table7[tuple(outputxor)]):
					table7[tuple(outputxor)].append(bj2value)
			elif (i==8):
				if(bj2value not in table8[tuple(outputxor)]):
					table8[tuple(outputxor)].append(bj2value)

#method to lookup the sbox table
def sbox(value, boxnumber):
	digits = list(value)
	#print "digits ",digits
	row = []
	row.append(digits[0])
	row.append(digits[5])
	lookuprow = decimal(row)
	col = []
	col.append(digits[1])
	col.append(digits[2])
	col.append(digits[3])
	col.append(digits[4])
	lookupcol = decimal(col)
	if(boxnumber == 1):
		sboxoutput = sboxTable1[lookuprow][lookupcol]
	elif (boxnumber == 2):
		sboxoutput = sboxTable2[lookuprow][lookupcol]
	elif (boxnumber == 3):
		sboxoutput = sboxTable3[lookuprow][lookupcol]
	elif (boxnumber == 4):
		sboxoutput = sboxTable4[lookuprow][lookupcol]
	elif (boxnumber == 5):
		sboxoutput = sboxTable5[lookuprow][lookupcol]
	elif (boxnumber == 6):
		sboxoutput = sboxTable6[lookuprow][lookupcol]
	elif (boxnumber == 7):
		sboxoutput = sboxTable7[lookuprow][lookupcol]
	elif (boxnumber == 8):
		sboxoutput = sboxTable8[lookuprow][lookupcol]
	
	return sboxoutput

#method to do the xor of two values
def xor(value1,value2):
	if(isinstance(value1,tuple) or isinstance(value2, tuple)):
		digits = list(value1)
		digits2 = list(value2)
	if(isinstance(value1[0],list)):
		digits = value1[0]
		if (not isinstance(value2[0],list)):
			digits2 = value2
	if(isinstance(value2[0],list)):
		digits2 = value2[0]
		if (not isinstance(value1[0],list)):
			digits = value1
	else:
		digits = value1
		digits2 = value2
	xorList = []
	i = 0
	while(i<len(digits)):	
		xorval = digits[i] ^ digits2[i]
		xorList.append(xorval)
		i = i+1
	return xorList

#method to find the intersection of the keys1,keys2,keys3. These keys are the possible keys for each of the ct, pt pairs
def find48bitsKey(keys1,keys2,keys3):
	Keyslist = {}
	for i in xrange(0,8):
		for value in keys1[i]:
			if value in keys2[i] and value in keys3[i]:
				Keyslist[i] = []
				Keyslist[i].append(value)
				break
	return Keyslist
	
def main():
	constructSboxes()
	inputPT_CT_pair1 = [[binary(int("0x748502cd",16))],[binary(int("0x38451097",16))],[binary(int("0x2e48787d",16))],[binary(int("0xfb8509e6",16))]]
	inputPT_CT_pair2 = [[binary(int("0x38747564",16))],[binary(int("0x38451097",16))],[binary(int("0xfc19cb45",16))],[binary(int("0xb6d9f494",16))]]
	inputPT_CT_pair3 = [[binary(int("0x357418da",16))],[binary(int("0x013fec86",16))],[binary(int("0x5a799643",16))],[binary(int("0x9823cf12",16))]]
	inputPT_CT_pair4 = [[binary(int("0x12549847",16))],[binary(int("0x013fec86",16))],[binary(int("0xae46e276",16))],[binary(int("0x16c26b04",16))]]
	inputPT_CT_pair5 = [[binary(int("0x48691102",16))],[binary(int("0x6acdff31",16))],[binary(int("0xac777016",16))],[binary(int("0x3ddc98e1",16))]]
	inputPT_CT_pair6 = [[binary(int("0x375bd31f",16))],[binary(int("0x6acdff31",16))],[binary(int("0x7d708f6d",16))],[binary(int("0x4bc7ef16",16))]]

	#pairs given in handout
	#inputPT_CT_pair1 = [[binary(int("0x748502cd",16))],[binary(int("0x38451097",16))],[binary(int("0x03c70306",16))],[binary(int("0xd8a09f10",16))]]
	#inputPT_CT_pair2 = [[binary(int("0x38747564",16))],[binary(int("0x38451097",16))],[binary(int("0x78560a09",16))],[binary(int("0x60e6d4cb",16))]]
	#inputPT_CT_pair3 = [[binary(int("0x357418da",16))],[binary(int("0x013fec86",16))],[binary(int("0xd8a31b2f",16))],[binary(int("0x28bbc5cf",16))]]
	#inputPT_CT_pair4 = [[binary(int("0x12549847",16))],[binary(int("0x013fec86",16))],[binary(int("0x0f317ac2",16))],[binary(int("0xb23cb944",16))]]
	#inputPT_CT_pair5 = [[binary(int("0x48691102",16))],[binary(int("0x6acdff31",16))],[binary(int("0x45fa285b",16))],[binary(int("0xe5adc730",16))]]
	#inputPT_CT_pair6 = [[binary(int("0x375bd31f",16))],[binary(int("0x6acdff31",16))],[binary(int("0x134f7915",16))],[binary(int("0xac253457",16))]]
	
	l0_1 = inputPT_CT_pair1[0] #plaintext1
	r0_1 = inputPT_CT_pair1[1]
	l3_1 = inputPT_CT_pair1[2] #ciphertext1
	r3_1 = inputPT_CT_pair1[3]
	l0_2 = inputPT_CT_pair2[0] #plaintext2
	r0_2 = inputPT_CT_pair2[1]
	l3_2 = inputPT_CT_pair2[2] #ciphertext2
	r3_2 = inputPT_CT_pair2[3]
	
	delta_r3 = xor(r3_1,r3_2)
	delta_l0 = xor(l0_1,l0_2)	
	
	l0_3 = inputPT_CT_pair3[0] #plaintext3
	r0_3 = inputPT_CT_pair3[1]
	l3_3 = inputPT_CT_pair3[2] #ciphertext3
	r3_3 = inputPT_CT_pair3[3]
	l0_4 = inputPT_CT_pair4[0] #plaintext4
	r0_4 = inputPT_CT_pair4[1]
	l3_4 = inputPT_CT_pair4[2] #ciphertext4
	r3_4 = inputPT_CT_pair4[3]
	
	delta1_r3 = xor(r3_3,r3_4)
	delta1_l0 = xor(l0_3,l0_4)
	
	
	l0_5 = inputPT_CT_pair5[0] #plaintext5
	r0_5 = inputPT_CT_pair5[1]
	l3_5 = inputPT_CT_pair5[2] #ciphertext5
	r3_5 = inputPT_CT_pair5[3]
	l0_6 = inputPT_CT_pair6[0] #plaintext6
	r0_6 = inputPT_CT_pair6[1]
	l3_6 = inputPT_CT_pair6[2] #ciphertext6
	r3_6 = inputPT_CT_pair6[3]
	
	delta2_r3 = xor(r3_5,r3_6)
	delta2_l0 = xor(l0_5,l0_6)

	keys1 = differentialCryptanalysis(l3_1,l3_2,delta_r3,delta_l0)
	keys2 = differentialCryptanalysis(l3_3,l3_4,delta1_r3,delta1_l0)
	keys3 = differentialCryptanalysis(l3_5,l3_6,delta2_r3,delta2_l0)

	#finding intersection set between the possible keys for ct pt pairs
	final48bitKey = {}
	final48bitKey = find48bitsKey(keys1,keys2,keys3)
	print "The 48 bit key value is "
	i = 0
	for value in final48bitKey.values():
		print i, " ", value[0]
		i = i + 1
	
	print "-*_*_*_*_*_*_*_*-*-*-*-*-*-*-*_*_*_*_*_*_*_*_*-*-*-*-*-*-*-*"
	
	final56bitkey = {}
	roundnumber = 3
	bitkey56 = reverseKeyScheduling(final48bitKey,roundnumber)
	
	#brute forcing for the rest of the 8 bits
	plaintextpair1 = []
	plaintextpair1.append(l0_1[0])
	plaintextpair1.append(r0_1[0])
	ciphertextpair1 = []
	ciphertextpair1.append(l3_1[0])
	ciphertextpair1.append(r3_1[0])

	final56bitkey = bruteforce(bitkey56, plaintextpair1, ciphertextpair1)
	final56bitkey = setParity(final56bitkey)
	
	masterkey_56 = []
	#formatting the final 56 bit key by unpacking all the bits into a list
	for value in final56bitkey.values():
		for value1 in value:
			for value2 in value1:
				masterkey_56.append(value2)
		
	print "The final key after 3 round of DES for the given cipher text - plain text pairs is "
	
	i = 0
	for value in final56bitkey.values():
		print i, " ", value[0]
		i = i + 1
	
	print "-*_*_*_*_*_*_*_*-*-*-*-*-*-*-*-*_*_*_*_*_*_*_*-*-*-*-*-*-*-*_"
	
	#no pairty bits hexadecimal form of the key doesn't really turn up to the actual value unless pairty bits are introduced
	print "Hex form including the parity bits of the key are ", format(decimal(masterkey_56), '02x')

def setParity(key):
	finalkey = []
	finalkey = dividingBits(key,8)
	for value in finalkey.values():
		if(count(value)%2 == 0):
			for value2 in value:
				for value3 in value2:
					if value3 == None:
						value[0][7] = 1
		else:
			for value2 in value:
				for value3 in value2:
					if value3 == None:
						value[0][7] = 0
	return finalkey
	
def count(key):
	count = 0
	for value in key:
		for value1 in value:
			if value1 == 1:
				count = count + 1
	return count
	
#function to do the brute force for the 8 bits of the master key
def bruteforce(key_64, inputPlaintext,expectedCiphertext):
	finalkey = []
	lst = list(itertools.product([0, 1], repeat=8))
	bruteforcelist=[]
	for value in lst:
		for value2 in value:
			bruteforcelist.append(value2)
	i = 1
	bruteforcepointer = 0
	key = []
	for value in key_64:
		key.append(value)

	while(i<=256):
		j = 1
		for value in key_64:
			if j%8 != 0:
				if value == None:
					#replace these bits with 0s and 1s in a variable called key
					key[j-1] = bruteforcelist[bruteforcepointer]
					bruteforcepointer = bruteforcepointer + 1				
			j = j + 1
		if(encrypt3DES(inputPlaintext,key) == expectedCiphertext):
			for value in key:
				finalkey.append(value)
			break
		i = i + 1
	return finalkey

#method to encrypt the plain text using 3 round DES, returns the cipher text
def encrypt3DES(inputPlaintext,key):
	encryptedtext = []
	l0_1 = inputPlaintext[0]
	r0_1 = inputPlaintext[1]
	Evalue = []
	inputxor = []

#applying 3 rounds
	for i in xrange(1,4):		
		#expansion of the right 32 bits
		Evalue = expansion(r0_1)
		
		#getting the round key
		key48bit = getroundKey(key,i)
		
		#applying xor on round key and expanded bits
		inputxor = xor(Evalue,key48bit)
		
		#dividing them into chunks to send them into s boxes
		inputxor_chunks = []
		inputxor_chunks = dividingBits(inputxor,6)
		
		cvalues_chunks= []
		cvalues = []
		
		#applying the 8 S-boxes
		for x in xrange(0,8):
			cvalues_chunks.append(binary(sbox(inputxor_chunks[x][0],x+1)))

		for value in cvalues_chunks:
			for value1 in value:
				cvalues.append(value1)
		
		#now applying permutation on the cvalues
		outputofFunction = Permutation(cvalues,p,32)
		
		#composing the output of the round
		temporaryLeftBits = l0_1
		l0_1 = r0_1
		r0_1 = xor(outputofFunction,temporaryLeftBits)
		
	encryptedtext.append(l0_1)
	encryptedtext.append(r0_1)
	return encryptedtext

#method to do the keyScheduling to get the round key
def getroundKey(key,roundNumber):
	
	#applying the pc1 permutation
	pc1key = Permutation(key, pc1,56)
	
		#circular left shift each half once for i up to the round number but double shift all except 1,2,9 and 16
	for k in xrange(1,roundNumber+1):
		temp = pc1key[0]
		for i in xrange(0,28):
			pc1key[i] = pc1key[i+1]
		pc1key[27]=temp
		temp = pc1key[28]
		for i in xrange(28,55):
			pc1key[i]=pc1key[i+1]
		pc1key[55] = temp
		if k == 1 or k == 2 or k == 9 or k == 16 :
			continue
		temp = pc1key[0]
		for i in xrange(0,28):
			pc1key[i] = pc1key[i+1]
		pc1key[27]=temp
		temp = pc1key[28]
		for i in xrange(28,55):
			pc1key[i]=pc1key[i+1]
		pc1key[55] = temp

	#applying pc2 permutation
	pc2key = Permutation(pc1key,pc2,48)
	return pc2key
	
def Permutation(listforPermutation, permutationList, numberofbits):
	elementsAfterPerm = [None]*numberofbits
	for i in xrange(0,numberofbits):
		index = permutationList[i]
		elementsAfterPerm[i] = listforPermutation[index-1]
	return elementsAfterPerm

#method to do the reverseKeyScheduling
def reverseKeyScheduling(key,roundnumber):
	packedKey = []
	for value in key.values():
		for value1 in value:
			for value2 in value1:
				packedKey.append(value2)
	#applying the reverse permutation on PC2
	pc2_inverse_key = inversePermutation(packedKey, pc2, 56)
	#key is shifted 4 times for generating 3rd round key
	for x in xrange(0,4):
		rightshiftedKey = rightshift(pc2_inverse_key)
		pc2_inverse_key = rightshiftedKey
		
	#applying the reverse permutation on PC1
	pc1_inverse_key = inversePermutation(rightshiftedKey, pc1, 64)
	return pc1_inverse_key

#method to do the right shift, used in reverse key scheduling    
def rightshift(s):
	s_shifted = [None]*56
	s_shifted[0]=s[27]
	for i in xrange(0,28):
		s_shifted[i+1] = s[i]	
	s_shifted[28]=s[55]
	for j in xrange(28,55):
		s_shifted[j+1] = s[j]
	return s_shifted

#function to do the inversePermutation
def inversePermutation(functionoutput, permutationList, numberofbits):
	elementsAfterInversePerm = [None]*numberofbits
	i = 0
	for value in permutationList:
		if(functionoutput[i] != None):
			elementsAfterInversePerm[value-1] = functionoutput[i]
		i = i + 1
	return elementsAfterInversePerm

#function to get all the possible key values - by looking up at the constructed tally realization tables
def getPossibleKeys(outputXor, sboxnumber, evalues):
	keyslist = []
	if(sboxnumber == 1):
		for value in table1[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 2):
		for value in table2[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 3):
		for value in table3[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 4):
		for value in table4[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 5):
		for value in table5[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 6):
		for value in table6[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 7):
		for value in table7[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	elif (sboxnumber == 8):
		for value in table8[tuple(outputXor[0])]:
			keyslist.append(xor(value,evalues))
	return keyslist

#method to apply the expansion function on 32 bits to get 48 bits
def expansion(valueList):
	expandedlist = [None]*48
	i = 0
	for value in expansionFunction:
		expandedlist[i] = valueList[value-1]
		i = i + 1
	return expandedlist

def dividingBits(list_fordivision,number):
	i = 0
	j = 0
	sublist = []
	listofchunks = {}
	for value in list_fordivision:
		sublist.append(value)
		if((i+1) % number == 0):
			listofchunks[j] = []
			listofchunks[j].append(sublist)
			j = j + 1
			sublist = []
		i = i + 1
	return listofchunks

#function to do the differential cryptanalysis attack, this returns all the possible key values
def differentialCryptanalysis(value1_l3,value2_l3,delta_R3,delta_l0):
	#applying the expansion function on the 32 bit inputs
	e1_value = (expansion(value1_l3[0]))
	e2_value = (expansion(value2_l3[0])) #e1 and e2 are lists

	deltaBj = xor(e1_value, e2_value) #Bj` value

	#dividing Ej values into 8 chunks of 6 bits each
	evalues = {}
	evalues = dividingBits(e1_value,6)
	
	#dividing Bj` into 8 chunks, constructing a list of lists
	bjlist = {}
	bjlist = dividingBits(deltaBj,6)

	#output xor values from the s boxes
	functionoutput = xor(delta_R3,delta_l0)
 
	deltaCj = inversePermutation(functionoutput,p,32)
	
	#dividng into chunks so we get 8 Cj` values
	cjlist = {}
	cjlist = dividingBits(deltaCj,4)

	#Now we have the 8 Bj` values and 8 Cj` values
	#Now, we need to look up the table
	keyslist = {}
	for i in xrange(0,8):
		constructMapTables(bjlist[i]) #we are constructing the tally realization INj tables only for this Bj`
		keyslist[i]=getPossibleKeys(cjlist[i],i+1,evalues[i])
	return keyslist
main()
