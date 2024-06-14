import hashlib
import os


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

    return fixed_key.encode()

def xor_bytes(block, key):
    # melakukan xor block plaintext dengan key
    return bytes([x ^ y for x, y in zip(block, key)])

def encrypt(plaintext, iv, key, ascii_key):
    plaintext_bytes = plaintext.encode()  # Konversi plaintext menjadi bytes
    ciphertext = b''
    prev_block = iv
    for i in range(0, len(plaintext_bytes), 16):
        block = plaintext_bytes[i:i+16]  # Ambil blok 8 byte
        if len(block) < 16:
            block += b' ' * (16 - len(block))  # Tambahkan padding jika perlu
        block_xor_iv = xor_bytes(block, prev_block)  # XOR dengan IV atau blok sebelumnya
        block_xor_key = xor_bytes(block_xor_iv, key)  # XOR dengan kunci
        block_ascii = xor_bytes(block_xor_key, ascii_key)  # XOR dengan kunci ASCII
        ciphertext += block_ascii  # Tambahkan blok yang telah dienkripsi ke ciphertext
        prev_block = block_ascii
    return ciphertext  # Kembalikan hanya ciphertext

def decrypt(encrypted_data, iv, key, ascii_key):
    plaintext_bytes = b''
    prev_block = iv
    for i in range(0, len(encrypted_data), 16):
        block = encrypted_data[i:i+16]  # Ambil blok 8 byte
        block_xor_ascii = xor_bytes(block, ascii_key)  # XOR dengan kunci ASCII
        block_xor_key = xor_bytes(block_xor_ascii, key)  # XOR dengan kunci
        plaintext_block = xor_bytes(block_xor_key, prev_block)  # XOR dengan IV atau blok ciphertext sebelumnya
        plaintext_bytes += plaintext_block
        prev_block = block
    return plaintext_bytes.rstrip(b' ').decode()  # Hilangkan padding dan konversi kembali ke string

# Contoh penggunaan
key = create_key_128("ini kunci rahasia")
iv = os.urandom(16)
ascii_key =  create_key_128("ini ascii") # Menghasilkan kunci ASCII acak sepanjang 16 byte

# Input dari pengguna
plaintext = open("plaintext.txt", "r", encoding="utf-8")
plaintext = str(plaintext.read())

# Mengenkripsi plaintext
ciphertext = encrypt(plaintext, iv, key, ascii_key)
print("Ciphertext:", ciphertext.hex())  # Mencetak ciphertext dalam format heksadesimal

# mendekripsi ciphertext
decrypted_text = decrypt(ciphertext, iv, key, ascii_key)
print("Decrypted text:", decrypted_text) # Mencetak ciphertext dalam format heksadesimal