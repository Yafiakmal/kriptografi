import os

def generate_key():
    return os.urandom(8)  # 8 bytes untuk kunci

def generate_iv():
    return os.urandom(8)  # 8 bytes untuk IV

def generate_ascii_key():
    return os.urandom(8)  # Menghasilkan 8 byte acak sebagai kunci ASCII

def xor_bytes(data, key):
    # melakukan xor block plaintext dengan key
    return bytes([x ^ y for x, y in zip(data, key)])

def encrypt(plaintext, iv, key, ascii_key):
    plaintext_bytes = plaintext.encode()  # Konversi plaintext menjadi bytes
    ciphertext = b''
    prev_block = iv
    for i in range(0, len(plaintext_bytes), 8):
        block = plaintext_bytes[i:i+8]  # Ambil blok 8 byte
        if len(block) < 8:
            block += b' ' * (8 - len(block))  # Tambahkan padding jika perlu
        block_xor_iv = xor_bytes(block, prev_block)  # XOR dengan IV atau blok sebelumnya
        block_xor_key = xor_bytes(block_xor_iv, key)  # XOR dengan kunci
        block_ascii = xor_bytes(block_xor_key, ascii_key)  # XOR dengan kunci ASCII
        ciphertext += block_ascii  #Tambahkan blok yang telah dienkripsi ke ciphertext
        prev_block = block_ascii 
    return ciphertext  # Kembalikan hanya ciphertext

def decrypt(encrypted_data, iv, key, ascii_key):
    plaintext_bytes = b''
    prev_block = iv
    for i in range(0, len(encrypted_data), 8):
        block = encrypted_data[i:i+8]  # Ambil blok 8 byte
        block_xor_ascii = xor_bytes(block, ascii_key)  # XOR dengan kunci ASCII
        block_xor_key = xor_bytes(block_xor_ascii, key)  # XOR dengan kunci
        plaintext_block = xor_bytes(block_xor_key, prev_block)  # XOR dengan IV atau blok ciphertext sebelumnya
        plaintext_bytes += plaintext_block
        prev_block = block
    return plaintext_bytes.rstrip(b' ').decode()  # Hilangkan padding dan konversi kembali ke string

# Contoh penggunaan
key = generate_key()
iv = generate_iv()
ascii_key = generate_ascii_key()  # Menghasilkan kunci ASCII acak sepanjang 8 byte

# Input dari pengguna
plaintext = input("Masukkan teks yang akan dienkripsi: ")

# Mengenkripsi plaintext
ciphertext = encrypt(plaintext, iv, key, ascii_key)
print("Ciphertext:", ciphertext.hex())  # Mencetak ciphertext dalam format heksadesimal

# Mendekripsi ciphertext
decrypted_text = decrypt(ciphertext, iv, key, ascii_key)
print("Decrypted text:", decrypted_text)  # Mencetak teks yang telah didekripsi