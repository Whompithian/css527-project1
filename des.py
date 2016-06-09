#! /usr/bin/env python3.3

"""DES implementation in Python by Brendan Sweeney, CSS 527, Assignment 1.

Command-line driven implementation of the DES encryption algorithm in cipher-
block chaining mode. There are three modes of operation: genkey, encrypt, and
decrypt. genkey mode takes a password on the command line and derives a DES key
from it, which is written to a file also specified on the command line. encrypt
and decrypt mode operate similarly, but are not true inverses, i.e. performing
decryption on a plain text file and encrypting the resulting ciphertext will
not result in the original plain text. Both modes require an input file, which
should be plain text for encrypt and ciphertext for decrypt, a key file, and an
output file, which needs to be writeable or creatable. Output is silent on
success. Basic help is available by calling the program with an operating mode
followed by the -h flag.
    
Keyword arguments:
mode -- The mode of operation. May be genkey, encrypt, or decrypt.
password -- For genkey mode, only. A password from which to derive a DES
            encryption key.
inputFile -- For encrypt and decrypt modes. A file containing either the plain
              text to be encrypted or ciphertext to be decrypted.
keyFile -- For encrypt and decrypt modes. A file containing the DES encryption
           key to use to process the input file.
outputFile -- File to which the result of operation will be written. This will
              be the DES encryption key in genkey mode, ciphertext in encrypt
              mode, or plain text in (successful) decrypt mode. If the file
              already exists, it will be overwritten.
"""

from argparse import ArgumentParser, FileType
from hashlib import sha256
import random

# Initial Permutation
IP_TABLE = [
[58, 50, 42, 34, 26, 18, 10,  2],
[60, 52, 44, 36, 28, 20, 12,  4],
[62, 54, 46, 38, 30, 22, 14,  6],
[64, 56, 48, 40, 32, 24, 16,  8],
[57, 49, 41, 33, 25, 17,  9,  1],
[59, 51, 43, 35, 27, 19, 11,  3],
[61, 53, 45, 37, 29, 21, 13,  5],
[63, 55, 47, 39, 31, 23, 15,  7]]

# Final Permutation
FP_TABLE = [
[40,  8, 48, 16, 56, 24, 64, 32],
[39,  7, 47, 15, 55, 23, 63, 31],
[38,  6, 46, 14, 54, 22, 62, 30],
[37,  5, 45, 13, 53, 21, 61, 29],
[36,  4, 44, 12, 52, 20, 60, 28],
[35,  3, 43, 11, 51, 19, 59, 27],
[34,  2, 42, 10, 50, 18, 58, 26],
[33,  1, 41,  9, 49, 17, 57, 25]]

# Expansion
E_TABLE = [
[32,  1,  2,  3,  4,  5,  4,  5],
[ 6,  7,  8,  9,  8,  9, 10, 11],
[12, 13, 12, 13, 14, 15, 16, 17],
[16, 17, 18, 19, 20, 21, 20, 21],
[22, 23, 24, 25, 24, 25, 26, 27],
[28, 29, 28, 29, 30, 31, 32,  1]]

# Round Permutation
P_TABLE = [
[16,  7, 20, 21, 29, 12, 28, 17],
[ 1, 15, 23, 26,  5, 18, 31, 10],
[ 2,  8, 24, 14, 32, 27,  3,  9],
[19, 13, 30,  6, 22, 11,  4, 25]]

# Permuted Choice 1
PC1_TABLE = [
[57, 49, 41, 33, 25, 17,  9,  1],
[58, 50, 42, 34, 26, 18, 10,  2],
[59, 51, 43, 35, 27, 19, 11,  3],
[60, 52, 44, 36, 63, 55, 47, 39],
[31, 23, 15,  7, 62, 54, 46, 38],
[30, 22, 14,  6, 61, 53, 45, 37],
[29, 21, 13,  5, 28, 20, 12,  4]]

# Permuted Choice 2
PC2_TABLE = [
[14, 17, 11, 24,  1,  5,  3, 28],
[15,  6, 21, 10, 23, 19, 12,  4],
[26,  8, 16,  7, 27, 20, 13,  2],
[41, 52, 31, 37, 47, 55, 30, 40],
[51, 45, 33, 48, 44, 49, 39, 56],
[34, 53, 46, 42, 50, 36, 29, 32]]

# Key Schedule
KS_TABLE = [
[ 1, 1],
[ 2, 1],
[ 3, 2],
[ 4, 2],
[ 5, 2],
[ 6, 2],
[ 7, 2],
[ 8, 2],
[ 9, 1],
[10, 2],
[11, 2],
[12, 2],
[13, 2],
[14, 2],
[15, 2],
[16, 1]]

# S-Boxes 1-8
S1_TABLE = [
[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
[ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
[ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
[15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]]

S2_TABLE = [
[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
[ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
[ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
[13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]]

S3_TABLE = [
[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
[13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
[13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
[ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]]

S4_TABLE = [
[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
[13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
[10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
[ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]]

S5_TABLE = [
[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
[14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
[ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
[11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]]

S6_TABLE = [
[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
[10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
[ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
[ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]]

S7_TABLE = [
[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
[13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
[ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
[ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]]

S8_TABLE = [
[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
[ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
[ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
[ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]

# For iterating through bytes a bit at a time
BYTE_LEN = 8
# Number of bytes in a block of data
BLOCK_SIZE = 8
# Number of bytes in a DES key
KEY_SIZE = 7
# Number of bytes in a round key
RKEY_SIZE = 6
# Number of rounds of main encryption algorithm
NUM_ROUNDS = 16



def main():
    """Read command line to determine operating mode and take proper action."""
    
    # Setup initial parser to determine mode of operation
    parser = ArgumentParser(description="""Generate DES key from a passphrase\
                            and use it to encrypt or decrypt a file.""",
                            prefix_chars='%%', add_help=False)
    parser.add_argument('mode', choices=['decrypt', 'encrypt', 'genkey'],
        help="Tell %(prog)s in which mode it should operate.")
    parser.add_argument('source', nargs='?',
        help="Password text or file on which %(prog)s will operate.",
        metavar='password|keyFile')
    parser.add_argument('inputFile', nargs='?',
        help="The plain or encrypted file on which %(prog)s will operate.")
    parser.add_argument('outputFile', nargs='?',
        help="The file to which %(prog)s will write its results.")
    
    # Setup a parser for the key generation operation
    genkey = ArgumentParser(description="""Generate DES key from a passphrase\
                                           and save it to a file.""")
    genkey.add_argument('mode', choices=['genkey'],
        help="Tell %(prog)s to operate in key generation mode.")
    genkey.add_argument('password',
        help="The password that will be used to derive a DES encryption key.")
    genkey.add_argument('outputFile', type=FileType('wb'),
        help="The file in which to write the DES encryption key.")
    
    # Setup a parser for the cryptographic operations
    crypto = ArgumentParser(description="""Encrypt or decrypt a file using a\
                                           key saved in a specified file.""")
    crypto.add_argument('mode', choices=['decrypt', 'encrypt'],
        help="Tell %(prog)s whether to operate in encrypt or decrypt mode.")
    crypto.add_argument('inputFile', type=FileType('rb'),
        help="The file from which to read a message, plain or encrypted.")
    crypto.add_argument('keyFile', type=FileType('rb'),
        help="The file from which to read a DES encryption key.")
    crypto.add_argument('outputFile', type=FileType('wb'),
        help="The file in which to write a message, plain or encrypted.")
    
    # First pass through command line arguments to determine operating mode
    mode = parser.parse_args()
    random.seed()
    
    if mode.mode == 'decrypt':
        args = crypto.parse_args()
        decrypt(args.inputFile, args.keyFile, args.outputFile)
    elif mode.mode == 'encrypt':
        args = crypto.parse_args()
        encrypt(args.inputFile, args.keyFile, args.outputFile)
    else:
        # Only three modes of operation permitted by parser; must be genkey
        args = genkey.parse_args()
        gen_key(args.password, args.outputFile)



def decrypt(inputFile, keyFile, outputFile):
    """Decrypts a file that was encrypted with the provided key.
    
    DES decryption in CBC-mode. The provided input file needs to have been
    encrypted with DES in CBC-mode using the key in the provided key file. The
    output file must be writable. If it already exists, it will be overwritten.
    
    Keyword arguments:
    inputFile -- A file containing a multiple of 64 bits ofciphertext to be
                 decrypted.
    keyFile -- A file containing the 56-bit DES encryption key that was used to
               encrypt the input file.
    outputFile -- File to which decrypted plain text will be written. If the
                  file already exists, it will be overwritten.
    """
    
    # One block of plain text
    T = bytearray(BLOCK_SIZE)
    # One block of ciphertext
    C = bytearray(BLOCK_SIZE)
    # Convenient place for previous blocks for CBC XOR
    Cprev = bytearray(BLOCK_SIZE)
    key = bytearray(KEY_SIZE)
    # Initialization vector expected as first block of input file
    inputFile.readinto(Cprev)
    # First block of actual ciphertext
    eof = inputFile.readinto(C) < len(C)
    keyFile.readinto(key)
    # Permuted choice 1 performed here to avoid running each round, each block
    K = PC1(key)
    
    while not eof:
        # Initial permutation on ciphertext
        Cp = IP(C)
        # Right and left refer to plain text; they are swapped in ciphertext
        Rn, Ln = Cp[:BLOCK_SIZE // 2], Cp[BLOCK_SIZE // 2:]
        
        # Round order reversed for decryption
        for round in reversed(range(NUM_ROUNDS)):
            Rtemp, Ltemp = Rn[:], Ln[:]
            # Round key always derived from PC1(key), K, in the key schedule
            Rn, Ln = Ltemp[:], f(Ltemp, KS(round + 1, K))
            
            # XOR is performed one byte at a time
            for i in range(BLOCK_SIZE // 2):
                Ln[i] = Rtemp[i] ^ Ln[i]

        # T' is formed from the proper order of the preout plain text
        Tp = Ln[:]
        
        for node in Rn:
            Tp.append(node)
        
        # Still not true plain text; must go through CBC XOR step
        T = FP(Tp)
        
        # XOR previous block (or IV) with current block for CBC mode
        for i in range(BLOCK_SIZE):
            T[i] = T[i] ^ Cprev[i]

        # Check for and remove padding
        if T[len(T) - 1] <= BLOCK_SIZE and len(inputFile.peek(BLOCK_SIZE)) < 1:
            # This is the last block; only write bytes before padding
            outputFile.write(T[:(BLOCK_SIZE - T[len(T) - 1])])
        else:
            outputFile.write(T)
        
        # For CBC XOR of next block
        Cprev = C[:]
        # Can only work with whole blocks; anything extra is silently discarded
        eof = inputFile.readinto(C) < len(C)



def encrypt(inputFile, keyFile, outputFile):
    """Encrypts a file with the provided key and saves as another file.
    
    DES encryption in CBC-mode. The provided input file may need to be padded
    to a multiple of 64 bits before it can be encrypted with DES in CBC-mode
    using the key in the provided key file. The output file must be writable.
    If it already exists, it will be overwritten.
    
    Keyword arguments:
    inputFile -- A file containing plain text to be encrypted.
    keyFile -- A file containing the 56-bit DES encryption key that will be
               used to encrypt the input file.
    outputFile -- A file to which a multiple of 64 bits ofciphertext will be
                  written. If the file already exists, it will be overwritten.
    """
    
    # One block of plain text
    T = bytearray(BLOCK_SIZE)
    key = bytearray(KEY_SIZE)
    # One block of ciphertext, starting with initialization vector
    C = gen_iv()
    eof = keyFile.readinto(key) != KEY_SIZE
    # Permuted choice 1 performed here to avoid running each round, each block
    K = PC1(key)
    outputFile.write(C)
    
    while not eof:
        bytecount = inputFile.readinto(T)
        
        # Check for final block and pad it
        if bytecount < BLOCK_SIZE:
            T = pad(T, BLOCK_SIZE - bytecount)
            eof = True
        
        # XOR previous block (or IV) with current block for CBC mode
        for i in range(BLOCK_SIZE):
            T[i] = T[i] ^ C[i]

        # Initial permutation on plain text
        Tp = IP(T)
        Ln, Rn = Tp[:BLOCK_SIZE // 2], Tp[BLOCK_SIZE // 2:]
        
        for round in range(NUM_ROUNDS):
            Ltemp, Rtemp = Ln[:], Rn[:]
            Ln, Rn = Rtemp[:], f(Rtemp, KS(round + 1, K))
            
            # XOR is performed one byte at a time
            for i in range(BLOCK_SIZE // 2):
                Rn[i] = Ltemp[i] ^ Rn[i]

        # Flip the halves to get the preout ciphertext
        Cp = Rn[:]
        
        for node in Ln:
            Cp.append(node)
        
        # Save C for next block CBC XOR before writing to output file
        C = FP(Cp)
        outputFile.write(C)



def gen_key(password, outputFile):
    """Generate a DES encryption key from a password string.
    
    genkey derives a DES encryption key by hashing a plain text password or
    phrase, using sha256, and saving the frist 56 bits to a file. The hash is
    not salted and file permissions are not set for proper privacy, so this
    should not be considered a secure method of generating keys.
    
    Keyword arguments:
    password -- A plain text string used to derive a DES encryption key.
    outputFile -- A 7-byte to which a 56-bit DES encryption key is written.
                  Must be writable. If the file already exists, it will be
                  overwritten.
    """
    
    hash = sha256(password.encode())
    outputFile.write(hash.digest()[:KEY_SIZE])



def gen_iv():
    """Returns the 64-bit initialization vector for CBC-mode encryption.
    
    The IV is 1 block (64 bits) that will be stored at the beginning of the
    ciphertext file. To avoid generating identical IV though consecutive calls,
    gen_iv does not seed the RNG; this should be done before gen_iv is called.
    """
    
    iv = bytearray()
    
    for i in range(BLOCK_SIZE):
        iv.append(random.randrange(256))
    
    return iv



def pad(T, count):
    """Returns a 64-bit block padded to 8 bytes with PKCS#5 padding.
    
    pad assumes that its input is a byte array of length 8 and an integer
    between 1 and 8. The last count bytes of the array are assumed empty and
    will be overwritten with a byte representation of count. Some basic sanity
    checks are performed to avoid indexing out of bounds if this assumption is
    violated, but the results in that case are not defined.
    
    Keyword arguments:
    T -- A plain text string of 0 to 7 bytes in an 8-byte array.
    count -- The number of bytes at the tail of the input block to overwrite.
    """
    
    if count > 0 and count <= len(T):
        for i in range(count):
            T[len(T) - (i + 1)] = count
    
    return T



def f(R, k):
    """Returns a half-block of data that has undergone one round of encryption.
    
    The half-block is assumed to be 32 bits stored in a 4-byte array. The key
    is assumed to be 48 bits stored in a 6-byte array. These inputs should be
    ensured before calling f.
    
    Keyword arguments:
    R -- 32 bits of data to be run through a round of encryption.
    k -- The current round key to apply to the data during encryption.
    """
    
    # Get the expansion of R from 32 bits to 48 bits
    X = E(R)
    
    # XOR expanded half-block with the round key
    for i in range(RKEY_SIZE):
        X[i] = X[i] ^ k[i]
    
    # Run resulting 48 bits through S-boxes
    X = s(X)
    
    # Round permutation
    return P(X)



def s(X):
    """Returns a half-block byte array resulting from S-box functions.
    
    s pipes 48 bits of data, in 6-bit chunks, through 8 different S-boxes. The
    operations are closely tied to the structure of the S-boxes and the layout
    of the bits in the input, so this function uses a lot of precise bit
    manipulation and magic numbers. The S-boxes, themselves, are defined as
    two-dimensional arrays of integers outside this function. They should all
    contain exactly 4 rows and 16 columns.
    
    Keyword arguments:
    X -- 48 bits of data to be run through 8 S-boxes, in 6-bit chunks.
    """
    
    Xp = bytearray(4)
    
    # Process the first 6 bits in byte 0
    row = ((X[0] & (2**7)) >> 6) ^ ((X[0] & (2**2)) >> 2)
    column = ((X[0] & (2**7 - 1)) >> 4)
    Xp[0] = S1_TABLE[row][column] << 4
    
    # Process the last 2 bits in byte 0 and first 4 bits in byte 1
    row = (X[0] & (2**1)) & (X[1] ^ ((2**4) >> 4))
    column = ((X[0] & (2**1 - 1)) << 3) & (X[1] >> 5)
    Xp[0] = Xp[0] ^ S1_TABLE[row][column]
    
    # Process the last 4 bits in byte 1 and first 2 bits in byte 2
    row = ((X[1] & (2**3)) >> 2) ^ (X[2] & ((2**6) >> 6))
    column = ((X[1] & (2**3 - 1)) << 1) & (X[2] >> 7)
    Xp[1] = S1_TABLE[row][column] << 4
    
    # Process the last 6 bits in byte 2
    row = ((X[2] & (2**5)) >> 4) ^ (X[2] & (2**0))
    column = (X[2] & (2**5 - 1)) >> 1
    Xp[1] = Xp[1] ^ S1_TABLE[row][column]
    
    # Process the first 6 bits in byte 3
    row = ((X[3] & (2**7)) >> 6) ^ ((X[3] & (2**2)) >> 2)
    column = ((X[3] & (2**7 - 1)) >> 4)
    Xp[2] = S1_TABLE[row][column] << 4
    
    # Process the last 2 bits in byte 3 and first 4 bits in byte 4
    row = (X[3] & (2**1)) & (X[4] ^ ((2**4) >> 4))
    column = ((X[3] & (2**1 - 1)) << 3) & (X[4] >> 5)
    Xp[2] = Xp[2] ^ S1_TABLE[row][column]
    
    # Process the last 4 bits in byte 4 and first 2 bits in byte 5
    row = ((X[4] & (2**3)) >> 2) ^ (X[5] & ((2**6) >> 6))
    column = ((X[4] & (2**3 - 1)) << 1) & (X[5] >> 7)
    Xp[3] = S1_TABLE[row][column] << 4
    
    # Process the last 6 bits in byte 5
    row = ((X[5] & (2**5)) >> 4) ^ (X[5] & (2**0))
    column = (X[5] & (2**5 - 1)) >> 1
    Xp[3] = Xp[3] ^ S1_TABLE[row][column]
    
    return Xp



def t_lookup(pre_mut, table, parity=0):
    """Returns a bit string permutation based on a lookup table.
    
    t_lookup takes a bit string and applies a table lookup to determine where
    each bit will be placed in an output bit string. It is assumed that the
    table contains 8 columns, although row count may vary. It is also assumed
    that any value that appears in the input table is 1 greater than some valid
    bit index of the input bit string. This should be ensured be calling 
    l_lookup.
    
    Keyword: arguments
    pre_mut -- A bit string to provide the input for the permutation.
    table -- A two-dimensional array of integers arranged in 8 columns. When
             read from left-to-right, top-to-bottom, each cell represents a bit
             position in the new bit string and the number contained in that
             cell represents the position of the bit in the original bit string
             from which to pull the value.
    parity -- Number of bits per byte that should be considered for parity,
              rather than part of the data string. Use with caution.
    """
    
    post_mut = bytearray(len(table))
    
    # Counting bytes in post_mut and rows in table
    for i in range(len(post_mut)):
        # Ensure content of 0 for bitwise operations
        post_mut[i] = 0
        
        # Counting bits in current byte and cells in table
        for j in range(BYTE_LEN):
            # Create a mask to isolate the current bit; assume big-endian
            mask = 2**(BYTE_LEN - (j + 1))
            # Lookup from where in pre_mut to pull the current bit
            mut = table[i][j] - 1
            # Isolate the target bit's byte-position; assume big-endian
            offset = BYTE_LEN - (mut % BYTE_LEN + 1)
            
            # adding parity allows skipping the parity bits
            if offset > (BYTE_LEN - (j + 1)):
                # Target bit is left of current bit; align them
                mask = mask & (pre_mut[mut // (BYTE_LEN + parity)] >> (
                                               offset - (BYTE_LEN - (j + 1))))
            elif offset < (BYTE_LEN - (j + 1)):
                # Target bit is right of current bit; align them
                mask = mask & (pre_mut[mut // (BYTE_LEN + parity)] << (
                                               BYTE_LEN - (j + 1) - offset))
            else:
                mask = mask & pre_mut[mut // (BYTE_LEN + parity)]
            
            # Match the current bit of the current byte to the original
            post_mut[i] = post_mut[i] ^ mask
    
    return post_mut



def IP(T):
    """Returns the initial permutation of a 64-bit block of input data.
    
    Used at the beginning of the encryption and decryption processes. A table
    lookup is performed to determine how bits in the input should be shifted.
    
    Keyword: arguments
    T -- A 64-bit block of data to be permutated. If T is less than 64 bits or
         not indexable, this will cause array index out of bounds errors.
    """
    
    return t_lookup(T, IP_TABLE)



def FP(Cp):
    """Returns the final permutation of a 64-bit block of input data.
    
    Used at the end of the encryption and decryption processes. A table lookup
    is performed to determine how bits in the input should be shifted.
    
    Keyword: arguments
    Cp -- A 64-bit block of data to be permutated. If Cp is less than 64 bits
          or not indexable, this will cause array index out of bounds errors.
    """
    
    return t_lookup(Cp, FP_TABLE)



def E(R):
    """Returns the round expansion of 32 bits of data to 48 bits of data.
    
    Used during the round function to prepare a half-block of data to be run
    through S-boxes. A table lookup is performed to determine how bits in the
    input should be expanded.
    
    Keyword: arguments
    R -- A 32-bit half-block of data to be expanded. If R is less than 32 bits
         or not indexable, this will cause array index out of bounds errors.
    """
    
    return t_lookup(R, E_TABLE)



def P(X):
    """Returns the round permutation of a 32-bit half-block of input data.
    
    Used at the end of the round function. A table lookup is performed to
    determine how bits in the input should be shifted.
    
    Keyword: arguments
    X -- A 32-bit half-block of data to be permutated. If X is less than 32
         bits or not indexable, this will cause array index out of bounds
         errors.
    """
    
    return t_lookup(X, P_TABLE)



def PC1(key):
    """Returns 56 shifted bits of the first permuted choice of a 56-bit key.
    
    Used during encryption and decryption to select the bits to use for the
    round key. A table lookup is performed to determine how bits in the input
    should be shifted.
    
    Keyword: arguments
    key -- A 56-bit DES encryption key stored in a 7-byte array. If key is less
    than 56 bits or not indexable, this will cause array index out of bounds
    errors.
    """
    
    # The table expects a 64-bit key, but parity of 1 allows for a 56-bit key
    return t_lookup(key, PC1_TABLE, 1)



def PC2(key):
    """Returns 48 bits of the second permuted choice for round keys.
    
    Used during each round of encryption and decryption to select the bits to
    use for that round's key. A table lookup is performed to determine how bits
    in the input should be shifted.
    
    Keyword: arguments
    key -- 48 bits of a DES encryption key stored in a 6-byte array. If key is
    less than 48 bits or not indexable, this will cause array index out of
    bounds errors.
    """
    
    return t_lookup(key, PC2_TABLE)



def KS(n, key):
    """Returns the current round key selected from the key schedule.
    
    Used during each round of encryption and decryption to select the bits to
    use for that round's key. First, the bits in either half of the inpu key
    need to be left-rotated, according to the round number. The result of that
    rotation is then sent through the second permuted choice function.
    
    Keyword: arguments
    n -- The number of the current round of encryption or decryption, used to
         determine the number of rotations.
    key -- 56 shifted bits of a DES encryption key stored in a 6-byte array. If
    key is less than 56 bits or not indexable, this will cause array index out
    of bounds errors.
    """
    
    keyp = bytearray(KEY_SIZE)
    
    for i in range(n):
        keyp = lrotate(keyp, KS_TABLE[i][1])
    
    return PC2(keyp)



def lrotate(key, steps):
    """Returns the left rotation of the provided permuted choice key.
    
    Used as part of the key schedule to select each round key. The key is
    treated as two separate parts, each containing 28 bits and receiving its
    own bit rotation. Since these operations should be fast, the resulting keys
    are not cached. Instead, each step is performed for each round in which it
    is required.
    
    Keyword: arguments
    key -- 56 bits of a DES encryption key stored in a 7-byte array.
    steps -- The number of places to rotate the bits; usually either 1 or 2.
    """
    
    keyp = key[:]
    fmask = 0
    hmask = 255
    
    # Left boundary masks to avoid losing bits during rotation
    for i in range(steps):
        fmask = fmask ^ (2**(7 - i))
        hmask = hmask ^ (2**(4 + i))
    
    # First six bytes can be shifted and right-fill in one step
    for k in range(6):
        keyp[k] = key[k] << steps
        keyp[k] = keyp[k] ^ ((key[k + 1] & fmask) >> (8 - steps))
    
    # Last byte needs to be right-fill from the middle (beginning of right key)
    keyp[6] = key[6] << steps
    keyp[6] = keyp[6] ^ ((key[3] & (fmask >> 4)) >> (4 - steps))
    # Middle byte needs to be middle-filled from the left
    keyp[3] = keyp[3] & hmask
    keyp[3] = keyp[3] ^ ((key[0] & fmask) >> (4 - steps))
    
    return keyp



# Script body is in main to bring it near the top and clearly group it
main()
