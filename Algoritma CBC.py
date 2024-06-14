def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def block_encrypt(block, key):
    return xor_bytes(block, key)

def block_decrypt(block, key):
    return xor_bytes(block, key)

def xor_ascii_bytes(data, key):
    ascii_key = key.encode('ascii')
    return bytes(data[i] ^ ascii_key[i % len(ascii_key)] for i in range(len(data)))

def encrypt_cbc(plaintext, key, iv):
    ciphertext = bytearray()
    prev_block = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        xor_block = xor_bytes(block, prev_block)
        encrypted_block = block_encrypt(xor_block, key)
        ciphertext.extend(encrypted_block)
        prev_block = encrypted_block
    return xor_ascii_bytes(ciphertext, 'your_ascii_key')

def decrypt_cbc(ciphertext, key, iv):
    ascii_key = 'your_ascii_key'.encode('ascii')
    ciphertext = bytes(c ^ ascii_key[i % len(ascii_key)] for i, c in enumerate(ciphertext))
    plaintext = bytearray()
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        encrypted_block = ciphertext[i:i + 16]
        decrypted_block = block_decrypt(encrypted_block, key)
        xor_block = xor_bytes(decrypted_block, prev_block)
        plaintext.extend(xor_block)
        prev_block = decrypted_block
    return bytes(plaintext)

# Input dari pengguna
key_input = input("Enter a 16-byte key (hex): ")
key = bytes.fromhex(key_input)

iv_input = input("Enter a 16-byte IV (hex): ")
iv = bytes.fromhex(iv_input)

plaintext = input("Enter a message to encrypt: ").encode()

ciphertext = encrypt_cbc(plaintext, key, iv)
print("Ciphertext:", ciphertext.hex())

decrypted_text = decrypt_cbc(ciphertext, key, iv)
print("Decrypted text:", decrypted_text.decode())
