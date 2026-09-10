"""
Companion experiment: AES-256-GCM per-message encryption/decryption
baseline timing.
Purpose: provide a like-for-like GCM (AEAD) companion to the existing
AES-256-CBC baseline for the reviewer response.
Method: replicates the timing harness of exp2_per_message_operations.py
exactly (warmup=3 / repeats=30 / time.perf_counter / os.urandom plaintext
fixed once per length / identical timing boundaries).
Notes: depends only on pycryptodome, does not import the paper's ncRNA
code, and only adds the results file results_aesgcm.json.
"""
import os
import sys
import json
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import assert_environment, set_threading_environment, timeit, machine_meta, RANDOM_SEED

import numpy as np
from Crypto.Cipher import AES

# Length ladder identical to Table S3 / exp2
DATA_LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]
NONCE_LEN = 12   # 96-bit GCM nonce
TAG_LEN = 16     # 128-bit GCM tag


def make_gcm_key():
    """Identical to the exp2 AES key derivation (scrypt, pre-generated, excluded from timing)."""
    return hashlib.scrypt(b'aes_password', salt=b'aes_salt_fixed16', n=2**14, r=8, p=1, dklen=32)


def selftest_tag_enforced(key):
    """
    Pre-timing self-test: confirm that GCM tag verification is mandatory
    (a tampered tag raises), so failures cannot pass silently.
    """
    pt = b'tag-enforcement-selftest'
    c = AES.new(key, AES.MODE_GCM, nonce=os.urandom(NONCE_LEN))
    ct, tag = c.encrypt_and_digest(pt)

    d = AES.new(key, AES.MODE_GCM, nonce=c.nonce)
    if d.decrypt(ct) != pt:
        raise RuntimeError("GCM self-test: correct tag failed to round-trip")
    d.verify(tag)  # correct tag: no exception

    bad = AES.new(key, AES.MODE_GCM, nonce=c.nonce)
    bad.decrypt(ct)
    try:
        bad.verify(bytes(b ^ 0xFF for b in tag))
    except ValueError:
        return
    raise RuntimeError("GCM tag verification did NOT reject a tampered tag")


def main():
    print("=" * 60)
    print("Companion experiment: AES-256-GCM per-message encryption/decryption baseline measurement")
    print("=" * 60)

    set_threading_environment()
    assert_environment()

    np.random.seed(RANDOM_SEED)

    gcm_key = make_gcm_key()
    selftest_tag_enforced(gcm_key)
    print(f"[SELFTEST] GCM tag enforcement OK (tampered tag rejected)")

    results = {
        'meta': {
            'experiment': 'AES-256-GCM Per-Message Encryption/Decryption Baseline (companion to exp2 AES-256-CBC)',
            'random_seed': RANDOM_SEED,
            'seed_convention': 'np.random.seed(20260909), identical to exp2; plaintexts drawn from os.urandom '
                               '(CSPRNG, not np.random) exactly as exp2 does, so the numpy seed has no effect on data',
            'repeats': 30,
            'warmup': 3,
            'data_lengths': DATA_LENGTHS,
            'key_bits': 256,
            'key_derivation': "hashlib.scrypt(b'aes_password', salt=b'aes_salt_fixed16', n=2**14, r=8, p=1, dklen=32) "
                              "- identical to exp2 AES-256-CBC, pre-generated outside timing",
            'nonce_bits': NONCE_LEN * 8,
            'nonce_freshness': 'new os.urandom(12) nonce per trial, generated INSIDE the timed region',
            'aad': None,
            'tag_bytes': TAG_LEN,
            'ciphertext_layout': 'ciphertext || 16-byte tag',
            'plaintext_generation': 'os.urandom(data_len), generated once per length outside timing - identical to exp2 '
                                    '(NOT random alphanumeric; exp2 convention retained per replication requirement)',
            'timing_scope_cbc': 'AES.new(key, MODE_CBC) object creation + internally generated random 16-byte IV + '
                                'PKCS#7 pad() + encrypt() + iv||ct concatenation; decrypt = object creation + decrypt() '
                                '+ unpad(). Key derivation excluded. (exp2_per_message_operations.py, lines 56-73)',
            'timing_scope_gcm': 'AES.new(key, MODE_GCM, nonce=os.urandom(12)) object creation + fresh random nonce + '
                                'encrypt() + digest() + ct||tag concatenation; decrypt = object creation + decrypt() + '
                                'verify(tag) (raises on failure). No padding on either side (GCM is a stream mode), '
                                'which is the functionally equivalent step to CBC pad/unpad. Key derivation excluded. '
                                'Thus both modes include object setup + one random IV/nonce draw + one pass over the data.',
            'tag_verification': 'mandatory; plaintext round-trip checked for every length before timing, tamper '
                                'self-test executed at startup',
            **machine_meta()
        },
        'measurements': {}
    }

    for data_len in DATA_LENGTHS:
        plaintext = os.urandom(data_len)

        # ---- Encryption: object construction + random nonce + encrypt + digest
        # (timing boundary equivalent to CBC) ----
        def gcm_encrypt_only():
            cipher = AES.new(gcm_key, AES.MODE_GCM, nonce=os.urandom(NONCE_LEN))
            ct = cipher.encrypt(plaintext)
            return ct + cipher.digest()

        enc_stats = timeit(gcm_encrypt_only, repeats=30, warmup=3)

        # ---- Decryption input (built once outside the timed region: random nonce + ciphertext + tag) ----
        nonce = os.urandom(NONCE_LEN)
        c_ref = AES.new(gcm_key, AES.MODE_GCM, nonce=nonce)
        ct = c_ref.encrypt(plaintext)
        tag = c_ref.digest()

        # Strict check: recovery must match byte-for-byte and the tag must verify; abort on any failure
        probe = AES.new(gcm_key, AES.MODE_GCM, nonce=nonce)
        recovered = probe.decrypt(ct)
        probe.verify(tag)
        if recovered != plaintext:
            raise RuntimeError(f"GCM decrypt round-trip mismatch at length {data_len}")

        # ---- Decryption: object construction + decrypt + verify(tag) (tag verification mandatory) ----
        def gcm_decrypt_only():
            cipher = AES.new(gcm_key, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt(ct)
            cipher.verify(tag)
            return pt

        dec_stats = timeit(gcm_decrypt_only, repeats=30, warmup=3)

        print(f"  {data_len:6d} bytes: enc={enc_stats['median']*1000:.3f} ms, dec={dec_stats['median']*1000:.3f} ms")

        results['measurements'][f'AES-GCM_{data_len}'] = {
            'data_length': data_len,
            'algorithm': 'AES-256-GCM',
            'encryption': enc_stats,
            'decryption': dec_stats
        }

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results_aesgcm.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)


if __name__ == '__main__':
    main()
