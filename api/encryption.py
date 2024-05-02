from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .conf import ENCRYPTION_KEY

def aes_encrypt(plaintext):
    """ 
    Encryption using the Advanced Encrytion Standard (AES),
    using the CBC mode of operation and PKCS7 padding scheme. 
    Adapted from Practical 4: Block Ciphers: DES and AES.

    :param plaintext:       String to be encrypted. Assumes "utf-8" format.
    :global ENCRYPTION_KEY: 128-bit key used for encryption.
    :return ciphertext:     String encrypted, in hexadecimal format.  
    """
    
    key_bytes = bytes(ENCRYPTION_KEY, "utf-8")
    plaintext_bytes = bytes(plaintext, "utf-8")

    aes_cipher = Cipher(algorithms.AES(key_bytes),
                    modes.CBC(bytearray(16)),
                    backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_bytes = padder.update(plaintext_bytes) + padder.finalize()
    ciphertext_bytes = aes_encryptor.update(padded_bytes) + aes_encryptor.finalize()
    ciphertext = ciphertext_bytes.hex()

    return ciphertext

def aes_decrypt(ciphertext):
    """ 
    Decryption using the Advanced Encrytion Standard (AES),
    using the CBC mode of operation and PKCS7 padding scheme. 
    Adapted from Practical 4: Block Ciphers: DES and AES.

    :param ciphertext:      String to be decrypted. Assumes hexadecimal format.
    :global ENCRYPTION_KEY: 128-bit key used for decryption.
    :return plaintext:      String decrypted, in "utf-8" format.
    """

    key_bytes = bytes(ENCRYPTION_KEY, "utf-8")
    ciphertext_bytes = bytes.fromhex(ciphertext)

    aes_cipher = Cipher(algorithms.AES(key_bytes),
                    modes.CBC(bytearray(16)),
                    backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    padded_bytes = aes_decryptor.update(ciphertext_bytes) + aes_decryptor.finalize()
    plaintext_bytes = unpadder.update(padded_bytes) + unpadder.finalize()
    plaintext = str(plaintext_bytes, "utf-8")

    return plaintext

def hash_password(salt, password):
    """ 
    Password hashing using Scrypt.
    Adapted from Practical 9: Hashing.

    :param salt:     String hexadecimal representation of 16 random bytes.
    :param password: String to be hashed. Assumes "utf-8" format.
    :return key:     String hexadecimal representation of the hashed password.
    """

    password_bytes = bytes(password, "utf-8")
    salt_bytes = bytes.fromhex(salt)

    kdf = Scrypt(
        salt=salt_bytes,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    key = kdf.derive(password_bytes)
    key = key.hex()
    return key

def verify_hash(salt, password, hashed_password):
    """ 
    Password hashing verification using Scrypt.
    Adapted from Practical 9: Hashing.

    :param salt:            String hexadecimal representation of 16 random bytes.
    :param password:        String to be compared. Assumes "utf-8" format.
    :param hashed_password: String hexadecimal to be compared.
    :return Boolean:        True if keys match, returns False otherwise.
    """

    salt_bytes = bytes.fromhex(salt)
    password_bytes = bytes(password, "utf-8")
    hashed_password_bytes = bytes.fromhex(hashed_password)

    kdf = Scrypt(
        salt=salt_bytes,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    # Note: If keys do not match, raises cryptography.exceptions.InvalidKey exception and returns False.
    # If verify() is called more than once, it would raise a cryptography.exceptions.AlreadyFinalized exception.
    # However, this should never happen.
    try:
        return (kdf.verify(password_bytes, hashed_password_bytes) == None)
    except:
        return False