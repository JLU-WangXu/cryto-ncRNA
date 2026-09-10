"""
Companion experiment: Crypto-ncRNA full per-message pipeline timing
(PBKDF2 key establishment excluded).
Purpose: Table S3 currently reports only the ChaCha20 cipher layer
(0.2117 ms @100 KB); this experiment additionally measures the full
encryption pipeline (codon encoding -> S-box substitution ->
structure prediction/permutation -> ChaCha20 encryption -> checksum) and
the matching decryption pipeline, with a convention comparable to the
Table S3 columns.
Method: replicates the timing harness of exp2_per_message_operations.py
exactly (warmup=3 / repeats=30 / time.perf_counter / keys pre-generated /
one fixed plaintext per length, generated outside the timed region).
Notes: only adds the results file results_fullpipeline.json; the frozen
code is imported read-only (stubbed matplotlib, as in
ablation_measure/common.py).
"""
import contextlib
import io
import json
import os
import sys
import types
import importlib.util
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (assert_environment, set_threading_environment, timeit,
                    machine_meta, RANDOM_SEED)

import numpy as np
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# --- Read-only loading of the frozen code ---
REPO = Path("/lenovofs1/home/wangyq/npj_uncon_comput")
CODE_PATH = REPO / "version2" / "code" / "ncrna" / "ncRNA3.5.py"
FROZEN_MODULE_NAME = "ncrna35_frozen_fullpipe"

DATA_LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]
SBOX_SEED = "123456789"                     # v1 demo vector
SEED_SEQUENCE = "ACGU" * 8                  # v1 demo vector (32 nt)
SALT = b"salt_123"                          # v1 demo vector


def load_reference_module():
    """Read-only import of the frozen ncRNA3.5.py (file untouched), with matplotlib.pyplot stubbed for headless use."""
    if not CODE_PATH.is_file():
        raise RuntimeError(f"reference implementation missing: {CODE_PATH}")
    mpl = types.ModuleType("matplotlib")
    pyplot = types.ModuleType("matplotlib.pyplot")
    mpl.pyplot = pyplot
    sys.modules.setdefault("matplotlib", mpl)
    sys.modules.setdefault("matplotlib.pyplot", pyplot)
    code_dir = str(CODE_PATH.parent)
    if code_dir not in sys.path:
        sys.path.insert(0, code_dir)
    spec = importlib.util.spec_from_file_location(FROZEN_MODULE_NAME, CODE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    print("=" * 60)
    print("Companion experiment: Crypto-ncRNA full-pipeline per-message timing")
    print("=" * 60)

    set_threading_environment()
    assert_environment()
    np.random.seed(RANDOM_SEED)

    mod = load_reference_module()
    import hashlib
    code_sha = hashlib.sha256(CODE_PATH.read_bytes()).hexdigest()
    print(f"[ENV] frozen code sha256={code_sha[:16]}... (read-only import)")

    # ---- Key/matrix pre-generation (excluded from timing) ----
    key = mod.generate_dynamic_key_from_biological_data(SEED_SEQUENCE, SALT)
    matrix = mod.generate_codon_substitution_matrix(SBOX_SEED)
    print("[SETUP] key = PBKDF2-HMAC-SHA256(seed_sequence, salt, dkLen=32, count=1e5) -- pre-generated")
    print("[SETUP] substitution matrix from seed '123456789' -- pre-generated")

    results = {
        'meta': {
            'experiment': 'Crypto-ncRNA full-pipeline per-message cost (key establishment excluded)',
            'random_seed': RANDOM_SEED,
            'repeats': 30,
            'warmup': 3,
            'data_lengths': DATA_LENGTHS,
            'frozen_code_path': str(CODE_PATH),
            'frozen_code_sha256': code_sha,
            'frozen_code_access': 'read-only import (stubbed matplotlib.pyplot); file untouched',
            'sbox_seed': SBOX_SEED,
            'seed_sequence_length_nt': len(SEED_SEQUENCE),
            'key_derivation': 'PBKDF2-HMAC-SHA256(seed_sequence, salt, dkLen=32, count=1e5) - '
                              'pre-generated OUTSIDE the timed region (identical policy to '
                              'exp2_per_message_operations.py for all three schemes)',
            'timing_scope_encrypt': 'encode_plaintext_to_codons -> substitute_codons -> '
                                    'apply_rna_secondary_structure (structure prediction + '
                                    'permutation) -> cha_encrypt (fresh random 8-byte nonce drawn '
                                    'inside the timed region, identical nonce policy to the '
                                    'Table S3 cipher-layer column) -> add_checksum (SHA-256 over '
                                    'nonce||ciphertext)',
            'timing_scope_decrypt': 'verify_and_remove_checksum -> cha_decrypt -> '
                                    'inverse_rna_secondary_structure -> inverse_substitute_codons '
                                    '-> decode_codons_to_plaintext',
            'statistic': 'median over 30 trials, std ddof=1, all_times retained',
            'plaintext_generation': 'random printable ASCII (string.ascii_letters + string.digits), '
                                    'one fixed plaintext per length via random.Random(20260909 + '
                                    'length_index), generated OUTSIDE the timed region; exp2 uses '
                                    'os.urandom but the frozen encoder requires str, and the '
                                    'encoding/folding cost is length-driven, not value-driven',
            **machine_meta()
        },
        'measurements': {}
    }

    import random
    import string
    plaintext_alphabet = string.ascii_letters + string.digits
    for li, data_len in enumerate(DATA_LENGTHS):
        # One fixed plaintext per length, generated outside the timed region
        # (same convention as exp2); exp2's os.urandom returns bytes, whereas
        # the frozen encode_plaintext_to_codons accepts str only, so the same
        # printable-ASCII alphabet as ablation_measure/exp2 is used here (the
        # length-driven encoding/folding cost is independent of byte values)
        rng = random.Random(RANDOM_SEED + li)
        plaintext = ''.join(rng.choice(plaintext_alphabet) for _ in range(data_len))

        # ---- Encryption (full pipeline) ----
        def full_encrypt():
            codon_sequence = mod.encode_plaintext_to_codons(plaintext)
            substituted = mod.substitute_codons(codon_sequence, matrix)
            structured, indices_order = mod.apply_rna_secondary_structure(substituted)
            data_to_encrypt = ''.join(structured)
            encrypted = mod.cha_encrypt(data_to_encrypt, key)
            return mod.add_checksum(encrypted), indices_order

        enc_stats = timeit(full_encrypt, repeats=30, warmup=3)

        # ---- Correctness self-check before timing: encrypt -> decrypt round-trip ----
        package, indices_order = full_encrypt()
        with contextlib.redirect_stdout(io.StringIO()):
            enc_data = mod.verify_and_remove_checksum(package)

            def full_decrypt():
                codon_seq = mod.cha_decrypt(enc_data, key)
                unfolded = mod.inverse_rna_secondary_structure(codon_seq, indices_order)
                original_codons = mod.inverse_substitute_codons(unfolded, matrix)
                return mod.decode_codons_to_plaintext(original_codons)

            recovered = full_decrypt()
            if recovered != plaintext:
                raise RuntimeError(f"full-pipeline round-trip mismatch at length {data_len}")

            dec_stats = timeit(full_decrypt, repeats=30, warmup=3)
        n_codons = len(mod.encode_plaintext_to_codons(plaintext))
        print(f"  {data_len:6d} bytes: enc={enc_stats['median']*1000:.4f} ms, "
              f"dec={dec_stats['median']*1000:.4f} ms "
              f"(roundtrip OK; {n_codons} codons, package={len(package)} B)")

        results['measurements'][f'ncRNA_fullpipeline_{data_len}'] = {
            'data_length': data_len,
            'algorithm': 'Crypto-ncRNA (full pipeline, key establishment excluded)',
            'n_codon_symbols': n_codons,
            'package_length_bytes': len(package),
            'roundtrip_ok': True,
            'encryption': enc_stats,
            'decryption': dec_stats
        }

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'results_fullpipeline.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)


if __name__ == '__main__':
    main()
