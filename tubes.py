#============================================================
plaintext = open("plaintext.txt", "r", encoding="utf-8")
# print(plaintext)

#conv list ke string 
#conv string ke bytes
plaintext = str(plaintext.read())
# print(type(plaintext))
# print(plaintext)

#============================================================
#membuat hash kunci
import hashlib

def create_key_128(key):
    # Create a SHA-256 hash object
    hash_object = hashlib.sha256()

    # Update the hash object with the word bytes
    key_byte = key.encode('utf-8')
    hash_object.update(key_byte)

    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()

    # Extract the first 16 characters (128 bits) of the hash
    fixed_key = hash_hex[:16]

    return fixed_key
#============================================================
#verifikasi hash value dari pyblake2
def verify_key(key, expected_hash):

    hash_value=create_key_128(key)
    if hash_value == expected_hash:
        return True
    else :
        return False

#============================================================
# def add_padding(plaintext, block_size=16):
#     padding_size = block_size - len(plaintext)
#     if padding_size == 0:
#         return plaintext
#     else :
#         padding = padding_size * str(padding_size)
#         return "".join([plaintext, padding])
def add_padding(plaintext, block_size=16):

    padding_size = block_size - len(plaintext) % block_size

    padding = bytes([padding_size] * padding_size)

    return plaintext + padding.decode('utf-8')
#============================================================
#fungsi membagi plaintext menjadi block block
def divide_into_blocks(plaintext, block_size):
    blocks = []
    for i in range(0, len(plaintext), block_size):

        block = plaintext[i:i + block_size]

        blocks.append(block)

    return blocks
print(plaintext)
print(divide_into_blocks(plaintext, 16))

#============================================================
#fungsi melakukan xor
def xor_encrypt(text, key):

    encrypted_text = ""

    for i in range(len(text)):

        encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))

    return encrypted_text


def xor_decrypt(encrypted_text, key):

    decrypted_text = ""

    for i in range(len(encrypted_text)):

        decrypted_text += chr(ord(encrypted_text[i]) ^ ord(key[i % len(key)]))

    return decrypted_text
#============================================================
def ecb_xor_encrypt(plaintext, key):
    plaintext = divide_into_blocks(plaintext,16)
    result = []
    for i in plaintext:
        i = add_padding(i)
        result.append(xor_encrypt(i, key))
    return result

#============================================================
def ecb_xor_decrypt(encrypted_text, key):
    result = []
    for i in encrypted_text:
        result.append(xor_decrypt(i, key))
    return "".join(result)

#============================================================
# key_128=create_key_128("ini kunci sangat rahasia")
# #melakukan enkripsi
# encrypted_text = ecb_xor_encrypt(plaintext, key_128)
# print(encrypted_text)

# #melakukan dekripsi
# decrypted_text = ecb_xor_decrypt(encrypted_text, key_128)
# print(decrypted_text)