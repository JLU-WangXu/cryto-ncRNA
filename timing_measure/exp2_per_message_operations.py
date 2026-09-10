"""
Experiment 2: per-message encryption/decryption operations (keys are
pre-generated; only the operations themselves are timed).
Goal: pure encrypt/decrypt time for Crypto-ncRNA / AES-256-CBC /
RSA-2048, excluding KDF and keygen.
"""
import os
import sys
import json
import hashlib

sys.path.insert(0, os.path.dirname(__file__))
from common import assert_environment, set_threading_environment, timeit, machine_meta, RANDOM_SEED

import numpy as np
from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

def main():
    print("=" * 60)
    print("Experiment 2: per-message encryption/decryption measurement")
    print("=" * 60)

    set_threading_environment()
    assert_environment()

    np.random.seed(RANDOM_SEED)

    # Data-length ladder
    DATA_LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]

    results = {
        'meta': {
            'experiment': 'Per-Message Encryption/Decryption Cost',
            'random_seed': RANDOM_SEED,
            'repeats': 30,
            'warmup': 3,
            'data_lengths': DATA_LENGTHS,
            **machine_meta()
        },
        'measurements': {}
    }

    # ========== AES-256-CBC ==========
    print("\n[1] AES-256-CBC (key pre-generated)")

    # Pre-generate the key (scrypt excluded from timing)
    aes_key = hashlib.scrypt(b'aes_password', salt=b'aes_salt_fixed16', n=2**14, r=8, p=1, dklen=32)

    for data_len in DATA_LENGTHS:
        plaintext = os.urandom(data_len)

        # Encryption
        def aes_encrypt_only():
            cipher = AES.new(aes_key, AES.MODE_CBC)
            iv = cipher.iv
            ct = cipher.encrypt(pad(plaintext, AES.block_size))
            return iv + ct

        enc_stats = timeit(aes_encrypt_only, repeats=30, warmup=3)

        # Decryption (using the iv+ct produced above)
        iv_ct = aes_encrypt_only()
        iv = iv_ct[:AES.block_size]
        ct = iv_ct[AES.block_size:]

        def aes_decrypt_only():
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            unpad(cipher.decrypt(ct), AES.block_size)

        dec_stats = timeit(aes_decrypt_only, repeats=30, warmup=3)

        print(f"  {data_len:6d} bytes: enc={enc_stats['median']*1000:.3f} ms, dec={dec_stats['median']*1000:.3f} ms")

        results['measurements'][f'AES_{data_len}'] = {
            'data_length': data_len,
            'algorithm': 'AES-256-CBC',
            'encryption': enc_stats,
            'decryption': dec_stats
        }

    # ========== RSA-2048 ==========
    print("\n[2] RSA-2048 (key pair pre-generated)")

    # Pre-generate the key pair (keygen excluded from timing)
    rsa_key = RSA.generate(2048)
    rsa_public = rsa_key.publickey()
    cipher_rsa_enc = PKCS1_OAEP.new(rsa_public)
    cipher_rsa_dec = PKCS1_OAEP.new(rsa_key)

    for data_len in DATA_LENGTHS:
        plaintext = os.urandom(data_len)
        BLOCK_SIZE = 190  # RSA-2048 OAEP maximum plaintext block

        # Encryption (block-wise)
        def rsa_encrypt_only():
            encrypted_blocks = []
            for i in range(0, len(plaintext), BLOCK_SIZE):
                block = plaintext[i:i+BLOCK_SIZE]
                encrypted_blocks.append(cipher_rsa_enc.encrypt(block))
            return b"".join(encrypted_blocks)

        enc_stats = timeit(rsa_encrypt_only, repeats=30, warmup=3)

        # Decryption
        ciphertext = rsa_encrypt_only()
        CIPHER_BLOCK_SIZE = 256  # RSA-2048 ciphertext block size

        def rsa_decrypt_only():
            decrypted_blocks = []
            for i in range(0, len(ciphertext), CIPHER_BLOCK_SIZE):
                block = ciphertext[i:i+CIPHER_BLOCK_SIZE]
                decrypted_blocks.append(cipher_rsa_dec.decrypt(block))
            return b"".join(decrypted_blocks)

        dec_stats = timeit(rsa_decrypt_only, repeats=30, warmup=3)

        print(f"  {data_len:6d} bytes: enc={enc_stats['median']*1000:.3f} ms, dec={dec_stats['median']*1000:.3f} ms")

        results['measurements'][f'RSA_{data_len}'] = {
            'data_length': data_len,
            'algorithm': 'RSA-2048',
            'encryption': enc_stats,
            'decryption': dec_stats
        }

    # ========== Crypto-ncRNA reduced variant (ChaCha20 part only) ==========
    print("\n[3] Crypto-ncRNA reduced variant (key pre-generated, ChaCha20 encryption/decryption only)")
    print("    Note: the full pipeline also performs codon encoding, folding and permutation; only the core cryptographic layer is timed here")

    # Pre-generate the key (PBKDF2 excluded from timing)
    ncrna_key = PBKDF2(b'ncrna_seed', b'ncrna_salt_16byt', dkLen=32, count=100000, hmac_hash_module=SHA256)

    for data_len in DATA_LENGTHS:
        plaintext = os.urandom(data_len)

        # Encryption (ChaCha20)
        def ncrna_encrypt_only():
            cipher = ChaCha20.new(key=ncrna_key)
            nonce = cipher.nonce
            ct = cipher.encrypt(plaintext)
            return nonce + ct

        enc_stats = timeit(ncrna_encrypt_only, repeats=30, warmup=3)

        # Decryption
        nonce_ct = ncrna_encrypt_only()
        nonce = nonce_ct[:8]
        ct = nonce_ct[8:]

        def ncrna_decrypt_only():
            cipher = ChaCha20.new(key=ncrna_key, nonce=nonce)
            cipher.decrypt(ct)

        dec_stats = timeit(ncrna_decrypt_only, repeats=30, warmup=3)

        print(f"  {data_len:6d} bytes: enc={enc_stats['median']*1000:.3f} ms, dec={dec_stats['median']*1000:.3f} ms")

        results['measurements'][f'ncRNA_{data_len}'] = {
            'data_length': data_len,
            'algorithm': 'Crypto-ncRNA (ChaCha20 only)',
            'encryption': enc_stats,
            'decryption': dec_stats
        }

    # ========== Save results ==========
    output_path = os.path.join(os.path.dirname(__file__), 'exp2_results.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)

if __name__ == '__main__':
    main()
