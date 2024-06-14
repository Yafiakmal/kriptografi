#============================================================
plaintext = open("plaintext.txt", "r", encoding="utf-8")
plaintext = plaintext.read()
print(plaintext)
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
#verifikasi hash value
def verify_key(key, expected_hash):

    hash_value=create_key_128(key)
    if hash_value == expected_hash:
        return True
    else :
        return False

#============================================================
def add_padding(plaintext, block_size=16):
    #jika block plaintext kurang dari ukuran block/16byte maka panjang padding bisa kita simpulkan adalah ukuran block dikurangi panjang plaintext yang sudah dibagi
    padding_size = block_size - len(plaintext) #% block_size (tambahkan jika plaintext belum dibagi menjadi block)
    #padding yang ditambahkan ukuran padding itu sendiri sejumlah ukuran padding itu
    padding = bytes([padding_size] * padding_size)
    #hasil dari fungsi ini adalah gabungan plaintext dengan padding yang sudah diubah menjadi string (namun karena variabel <list> padding awal nya adalah integer, biasanya gk keliatan kalo diconvert jadi string utf-8)
    return plaintext + padding.decode('utf-8')

#============================================================
#fungsi membagi plaintext menjadi block block
def divide_into_blocks(plaintext, block_size):
    blocks = []
    #melakukan pengulangan dari karakter index ke 0 sampai index terakhir dengan iterasi perstep 16
    for i in range(0, len(plaintext), block_size):
        #mengambil nilai dari plaintext sebanyak 16 dari index terakhir.
        block = plaintext[i:i + block_size]

        blocks.append(block)

    return blocks
#============================================================
#fungsi melakukan xor
def xor_encrypt(plaintext, key):
    encrypted_text = ""
    #sepanjang plaintext block lakukan xor per karakter dengan key
    for i in range(len(plaintext)):
        #setiap karakter pada block plaintext akan diubah menjadi kode/angka unicode yang merepresentasikan sebuah karakter.
        #kemudian di xor dengan key
        #kemudian chr() untuk menjadikan 
        encrypted_text += chr(ord(plaintext[i]) ^ ord(key[i]))
    return encrypted_text


def xor_decrypt(encrypted_text, key):
    decrypted_text = ""

    for i in range(len(encrypted_text)):
        decrypted_text += chr(ord(encrypted_text[i]) ^ ord(key[i % len(key)]))
    return decrypted_text
#============================================================
def ecb_xor_encrypt(plaintext, key):
    #membagi plaintext menjadi block
    plaintext = divide_into_blocks(plaintext,16)
    result = []
    #iterasi pada setiap block
    for i in plaintext:
        #jika block kurang dari 16byte, fungsi padding akan ditambahkan otomatis 
        i = add_padding(i)
        #hasil xor akan dimasukan ke dalam list result
        result.append(xor_encrypt(i, key))
    return "".join(result)

#============================================================
def ecb_xor_decrypt(encrypted_text, key):
    encrypted_text = divide_into_blocks(encrypted_text,16)
    result = []
    #melakukan iterasi pada ciphertext yang berbentuk block
    for i in encrypted_text:
        #setiap block dilakukan dekripsi xor dengan key
        result.append(xor_decrypt(i, key))
    #hasilnya adalah gabungan dari setiap block yang sudah di dekripsi
    return "".join(result)

#============================================================
key_128=create_key_128("ini kunci sangat rahasia")
#melakukan enkripsi
encrypted_text = ecb_xor_encrypt(plaintext, key_128)
print("hasil enkripsi : ", (encrypted_text).encode())

#melakukan dekripsi
decrypted_text = ecb_xor_decrypt(encrypted_text, key_128)
print("hasil dekripsi : ",decrypted_text)