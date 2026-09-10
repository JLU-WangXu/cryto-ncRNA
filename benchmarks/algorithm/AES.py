# AES Encryption
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext, seed, salt):
    key = scrypt(seed.encode(), salt.encode(), 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(encrypted_data, seed, salt):
    iv = encrypted_data[:AES.block_size]
    key = scrypt(seed.encode(), salt.encode(), 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size).decode()
