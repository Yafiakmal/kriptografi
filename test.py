import base64

def string_to_binary(text):
    #mengubah karakter menjadi representasi 8bit
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_string(binary):
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def pad_key(key, length):
    if len(key) < length:
        return (key * (length // len(key))) + key[:length % len(key)]
    return key[:length]

def xor_bytes(byte1, byte2):
    return bytes([b1 ^ b2 for b1, b2 in zip(byte1, byte2)])

def encrypt(plain, key):
    print("Step 1: Original Plain Text:", plain_text)
    
    plain_binary = string_to_binary(plain)
    print("Step 2: Binary representation of Plain Text:", plain_binary)
    
    key_binary = string_to_binary(pad_key(key, len(plain_binary)))
    print("Step 3: Padded Binary representation of Key:", key_binary)
    
    initial_cipher = xor_bytes([int(plain_binary[i:i+8], 2) for i in range(0, len(plain_binary), 8)],
                                [int(key_binary[i:i+8], 2) for i in range(0, len(key_binary), 8)])
    print("Step 4: Initial Cipher as Bytes:", initial_cipher)
    
    key_xor_key = xor_bytes(key_binary.encode(), key_binary.encode())
    if 0 in initial_cipher:
        key_binary = base64.b64encode(key_binary.encode()).decode()
    
    final_cipher = xor_bytes(initial_cipher, key_xor_key)
    print("Step 5: Final Cipher as Bytes:", final_cipher)
    
    return final_cipher

def decrypt(ciphertext, key):
    key_binary = string_to_binary(pad_key(key, len(ciphertext)*8))
    key_xor_key = xor_bytes(key_binary.encode(), key_binary.encode())
    initial_cipher = xor_bytes(ciphertext, key_xor_key)
    decrypted_plain = xor_bytes(initial_cipher, [int(key_binary[i:i+8], 2) for i in range(0, len(key_binary), 8)])
    decrypted_text = binary_to_string(''.join(format(byte, '08b') for byte in decrypted_plain))

    return decrypted_text

# Test the encryption and decryption
plain_text = "lamutoloalslslss"
key = "secretkey"

cipher = encrypt(plain_text, key)
print("Cipher:", cipher)

decrypted_text = decrypt(cipher, key)
print("Decrypted Text:", decrypted_text)