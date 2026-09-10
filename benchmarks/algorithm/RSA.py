from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# RSA encryption function, concatenates the ciphertext internally
def rsa_encrypt(plaintext, block_size=190):
    """
    Encrypt data in blocks with a dynamically generated public key and concatenate the full ciphertext.

    Args:
        plaintext (str): Plaintext to be encrypted.
        block_size (int): Size of each encrypted block, default is 190.
    Returns:
        Tuple[bytes, bytes, bytes]: Concatenated ciphertext, public key and private key.
    """
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Encrypt in blocks and concatenate
    encrypted_blocks = [
        cipher_rsa.encrypt(plaintext[i:i + block_size].encode())
        for i in range(0, len(plaintext), block_size)
    ]
    encrypted_data = b"".join(encrypted_blocks)  # Concatenate the ciphertext
    return encrypted_data, public_key.export_key(), key.export_key()

# RSA decryption function, handles the concatenated ciphertext
def rsa_decrypt(encrypted_data, private_key_data, block_size=256):
    """
    Decrypt the concatenated ciphertext with the private key.

    Args:
        encrypted_data (bytes): Concatenated encrypted ciphertext.
        private_key_data (bytes): Private key data.
        block_size (int): Size of each ciphertext block, default is 256 bytes.
    Returns:
        str: The decrypted plaintext.
    """
    private_key = RSA.import_key(private_key_data)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Decrypt in blocks
    decrypted_blocks = [
        cipher_rsa.decrypt(encrypted_data[i:i + block_size]).decode()
        for i in range(0, len(encrypted_data), block_size)
    ]
    return ''.join(decrypted_blocks)
