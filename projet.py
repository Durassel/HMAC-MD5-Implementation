import math
import random
import os 

# Define encodage
enc = "iso-8859-1"

# Define r :
r =  [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
      5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
      4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
      6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]

# Define constants k (sinus) :
k = []
for i in range(0, 64):
    k.append(int(abs(math.sin(i+1)) * 2**32))

# Variables
var = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
ipad_content = 0x36
opad_content = 0x5c

# Left rotation during md5
def rotate(x, y):
    x &= 0xFFFFFFFF # Apply And (&) with : 1111...1111 (32 bits)
    # Apply : ((X shifted to the left by y bits) OR (X shifted to the right by 32 - y bits)) AND 1111...1111 (32 bits)
    return ((x<<y) | (x>>(32-y))) & 0xFFFFFFFF

# MD5 algorithm
def md5(message):
    # Block size
    block_size = 64
    # Preparation of the message
    message = bytearray(message) # Convert bytes in array byte
    original_length_bit_message = (8 * len(message)) & 0xffffffffffffffff
    # Add bit "1"
    message.append(0x80) # 1000 0000 in bits
    # Add bit "0" until the message size in bits is equal to 448 (mod 512)
    while len(message) % block_size != 56:
        message.append(0)
    # Add original length to the end of the message
    message += original_length_bit_message.to_bytes(8, byteorder='little')

    # Init messages with variables (defined previously)
    messageA = var[0]
    messageB = var[1]
    messageC = var[2]
    messageD = var[3]

    # Main loop : subdivide message
    for i in range(0, len(message), block_size):
        # Init a, b, c, d
        a = messageA
        b = messageB
        c = messageC
        d = messageD
        # Subdivide into words of 32-bit in little-endian
        w = message[i : i + block_size]
        for j in range(block_size):
            # According to j, apply a different formula
            if (0 <= j | j < 16):
                f = ((b & c) | (~b & d))
                g = j
            elif (j >= 16 | j < 32):
                f = ((d & b) | (~d & c))
                g = (5 * j + 1) % 16
            elif (j >= 32 | j < 48):
                f = (b ^ c ^ d)
                g = (3 * j + 5) % 16
            elif (j >= 48 | j < 64):
                f = (c ^ (b | (~d)))
                g = (7 * j) % 16
            # Apply left rotation
            tmp = (b+rotate(a+f+k[j]+int.from_bytes(w[4*g:4*g+4],
            byteorder='little'),r[j])) & 0xFFFFFFFF
            # Update a, b, c, d
            a, b, c, d = d, tmp, b, c
        # Add result to previous bloc
        messageA += a
        messageA &= 0xFFFFFFFF
        messageB += b
        messageB &= 0xFFFFFFFF
        messageC += c
        messageC &= 0xFFFFFFFF
        messageD += d
        messageD &= 0xFFFFFFFF
    # Concatenate blocs in little endian
    x = messageA + (messageB << 32) + (messageC << 64) + (messageD << 96)

    return x.to_bytes(16, byteorder='little')

# Return md5 in hexadecimal
def md5_to_hex(digest):
    return '{:032x}'.format(int.from_bytes(digest, byteorder='big'))

# Generate a random salt
def getSalt():
    size = random.randint(1, 10) # Generate a random salt size
    salt = ""
    for j in range(0, size): # Generate random char for each char of the salt
        salt += chr(random.randint(97, 122)) # 97 = a / 122 = z (ascii table)
    return salt

# HMAC algorithm
def hmac(key, message, hash_function):
    # Define block size
    block_size = 64
    # Define opad and ipad
    opad = bytearray()
    ipad = bytearray()

    if len(key) > block_size: # If length key > 64
        key = bytearray(hash_function(key)) # Remove to reach the block size of function h
    cpt = len(key)
    while block_size > cpt: # Add 0 to reach the block size of function h
        cpt += 1
        key += b"\x00"

    # Ipad is define like : 0x363636...36 / Opad is define like : 0x5c5c5c...5c
    for i in range(block_size):
        ipad.append(ipad_content ^ key[i]) # Do OR between ipad and key (each bit)
        opad.append(opad_content ^ key[i]) # Do OR between opad and key (each bit)
    # Formula : md5(opad + md5(ipad + message)) : + defines concatenation
    return hash_function(bytes(opad) + hash_function(bytes(ipad) + message))

# Return hmac in hexadecimal
def hmac_to_hex(digest):
    return digest.hex()

def convert_hex_to_ascii(h):
    chars_in_reverse = []
    while h != 0x0:
        chars_in_reverse.append(chr(h & 0xFF))
        h = h >> 8

    chars_in_reverse.reverse()
    return ''.join(chars_in_reverse)

if __name__ == '__main__':
    # Passwords storage
    passwords = []

    # Generate 100 passwords
    print("[number , md5 used , [md5+salt used , salt], [hmac with md5 used , key] ] password")
    for i in range(0, 100):
        id = "id" + str(i) # Create id for each password
        size = random.randint(7, 14) # Random size of password
        value = ""
        for j in range(0, size): # Create password
            value += chr(random.randint(33, 122)) # From ! (33) to z (122) in ascii table
        salt = getSalt() # Generate salt
        # Add all information to passwords array
        passwords.append([id, md5_to_hex(md5(bytes(value, enc))), [md5_to_hex(md5(bytes(value + salt, enc))), salt],
        hmac_to_hex(hmac(bytes(salt, enc), bytes(value, enc), md5))])
        # Print password
        print(passwords[i], value)

    # Test cases : https://tools.ietf.org/html/rfc2202
    print("")
    print("Test cases :")

    key = bytes(convert_hex_to_ascii(0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b), enc)
    message = b"Hi There"
    print("key : 0x" + key.hex())
    print("message : " + message.decode(enc))
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    key = b"Jefe"
    message = b"what do ya want for nothing?"
    print("key : " + key.decode(enc))
    print("message : " + message.decode(enc))
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    key = bytes(convert_hex_to_ascii(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa), enc)
    message = bytes(convert_hex_to_ascii(0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd), enc)
    print("key : " + key.hex())
    print("message : " + message.hex())
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    key = bytes(convert_hex_to_ascii(0x0102030405060708090a0b0c0d0e0f10111213141516171819), enc)
    message = bytes(convert_hex_to_ascii(0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd), enc)
    print("key : " + key.hex())
    print("message : " + message.hex())
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    key = bytes(convert_hex_to_ascii(0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c), enc)
    message = b"Test With Truncation"
    print("key : " + key.hex())
    print("message : " + message.decode(enc))
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")
    
    key = bytes(convert_hex_to_ascii(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa), enc)
    message = b"Test Using Larger Than Block-Size Key - Hash Key First"
    print("key : " + key.hex())
    print("message : " + message.decode(enc))
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    key = bytes(convert_hex_to_ascii(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa), enc)
    message = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    print("key : " + key.hex())
    print("message : " + message.decode(enc))
    print("hmac : " + hmac_to_hex(hmac(key, message, md5)))
    print("")

    os.system("pause")
