import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Function to create a 156-bit key from a password
def create_key_256(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"salt",
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to verify a hash value
def verify_key(password, expected_hash):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"salt",
        iterations=100000
    )
    key = kdf.derive(password.encode())
    return hashlib.sha256(key).hexdigest() == expected_hash

# Function to add PKCS#7 padding to a plaintext
def add_padding(plaintext, block_size=16):
    padding_size = block_size - len(plaintext) % block_size
    padding = bytes([padding_size] * padding_size)
    return plaintext + padding

# Function to remove PKCS#7 padding from a ciphertext
def remove_padding(ciphertext):
    padding_size = ord(ciphertext[-1])
    return ciphertext[:-padding_size]

# Function to perform XOR encryption on a plaintext block
def xor_encrypt(plaintext, key):
    return bytes([p ^ k for p, k in zip(plaintext, key)])

# Function to perform XOR decryption on a ciphertext block
def xor_decrypt(ciphertext, key):
    return bytes([c ^ k for c, k in zip(ciphertext, key)])

def ecb_fernet_encrypt(plaintext, key):

    f = Fernet(key)

    ciphertext = f.encrypt(plaintext)

    return ciphertext


def ecb_fernet_decrypt(ciphertext, key):

    f = Fernet(key)

    plaintext = f.decrypt(ciphertext)

    return plaintext

# Main program
password = "ini kunci sangat rahasia"
key = create_key_256(password)

plaintext = "Muhammad Yafi Akmal sangat pintar semoga ganteng dan baik hati"

# Encrypt the plaintext using ECB-Fernet-XOR
encrypted_text = ecb_fernet_encrypt(plaintext.encode(), key)

# Decrypt the encrypted text using ECB-Fernet-XOR
decrypted_text = ecb_fernet_decrypt(encrypted_text, key)

# Print the results
print("Plaintext:", plaintext)
print("Encrypted text:", encrypted_text)
print("Decrypted text:", decrypted_text.decode())