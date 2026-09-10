"""
Companion experiment: re-measurement of ciphertext entropy for the three
schemes (Shannon plug-in + min-entropy H_inf).
Purpose: reconcile with main-text Table S6 (tab:avg_entropy_si) and add
min-entropy.
Protocol: replicates the measurement convention of
version1/crypto-ncRNA/Test1.0/test_shang.py exactly --
      plaintext = fresh random alphanumeric string (ascii_letters+digits)
      per trial, length = data length;
      ncRNA ciphertext = frozen full-config pipeline output of encrypt()
      (includes the 32 B checksum);
      AES ciphertext = IV || PKCS7 ciphertext (AES-256-CBC);
      RSA ciphertext = 190 B plaintext blocks, OAEP-encrypted and
      concatenated (2048 bit, 256 B/block).
      The only deviation from v1: keys/key pair are pre-generated once
      (ciphertext entropy is key-independent) instead of per trial.
Metrics: Shannon entropy = per-byte frequency plug-in (frozen
      calculate_entropy), mean/median/std over the 30 trials; min-entropy
      H_inf = -log2(max_b p(b)) using byte frequencies pooled over all
      30 trials of a cell.
Notes: only adds results_entropy_recheck.json; the frozen code is imported
      read-only (stubbed matplotlib).
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
import random
import string
import sys
import types
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import assert_environment, set_threading_environment, machine_meta, RANDOM_SEED

import numpy as np
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import scrypt

REPO = Path("/lenovofs1/home/wangyq/npj_uncon_comput")
CODE_PATH = REPO / "version2" / "code" / "ncrna" / "ncRNA3.5.py"
FROZEN_MODULE_NAME = "ncrna35_frozen_entropy"

DATA_LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]
N_TRIALS = 30
PLAINTEXT_ALPHABET = string.ascii_letters + string.digits   # v1 test_shang.generate_random_string
RSA_BLOCK = 190                                             # v1 RSA.py rsa_encrypt(block_size=190)

# Main-text Table S6 (tab:avg_entropy_si) reference values, for per-length reconciliation
TABLE_S6_REFERENCE = {
    'Crypto-ncRNA': [7.230238137, 7.520643336, 7.906697071, 7.954174669,
                     7.990878249, 7.995409292, 7.99908728, 7.999546736],
    'AES': [6.029898017, 6.553651309, 7.603863355, 7.808256544,
            7.962331187, 7.981768972, 7.996283968, 7.998177172],
    'RSA': [7.166932575, 7.1746127, 7.739013967, 7.875851176,
            7.972694673, 7.986424963, 7.997251254, 7.998614323],
}
TOLERANCE = 0.01


def load_reference_module():
    """Read-only import of the frozen ncRNA3.5.py (file untouched), with matplotlib.pyplot stubbed."""
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


def shannon_plugin(data):
    """Plug-in byte-frequency Shannon entropy (same formula as the frozen calculate_entropy)."""
    return float(mod.calculate_entropy(data))


def min_entropy(pooled_bytes):
    """H_inf = -log2(max_b p(b)), with p(b) taken from pooled counts."""
    n = len(pooled_bytes)
    if n == 0:
        return 0.0
    counts = Counter(pooled_bytes)
    p_max = max(counts.values()) / n
    return float(-math.log2(p_max))


def pooled_stats(values):
    arr = np.asarray(values, dtype=float)
    return {
        'n': int(arr.size),
        'mean': float(arr.mean()),
        'median': float(np.median(arr)),
        'std': float(arr.std(ddof=1)) if arr.size > 1 else 0.0,
        'min': float(arr.min()),
        'max': float(arr.max()),
    }


def make_plaintext(rng, length):
    return ''.join(rng.choice(PLAINTEXT_ALPHABET) for _ in range(length))


if __name__ == '__main__':
    print("=" * 60)
    print("Companion experiment: three-scheme ciphertext entropy re-measurement (Shannon + min-entropy)")
    print("=" * 60)

    set_threading_environment()
    assert_environment()

    mod = load_reference_module()
    code_sha = hashlib.sha256(CODE_PATH.read_bytes()).hexdigest()
    print(f"[ENV] frozen code sha256={code_sha[:16]}... (read-only import)")

    setup_rng = random.Random(RANDOM_SEED)

    # ---- Pre-generate key material (once; entropy is independent of the key value) ----
    ncrna_sbox_seed = ''.join(setup_rng.choice(string.digits) for _ in range(32))
    ncrna_seed_sequence = ''.join(setup_rng.choice('ACGU') for _ in range(32))
    ncrna_salt = ''.join(setup_rng.choice(PLAINTEXT_ALPHABET) for _ in range(16))
    ncrna_key = mod.generate_dynamic_key_from_biological_data(ncrna_seed_sequence,
                                                              ncrna_salt.encode())
    ncrna_matrix = mod.generate_codon_substitution_matrix(ncrna_sbox_seed)

    aes_seed = ''.join(setup_rng.choice(string.digits) for _ in range(32))
    aes_salt = ''.join(setup_rng.choice(PLAINTEXT_ALPHABET) for _ in range(16))
    aes_key = scrypt(aes_seed.encode(), aes_salt.encode(), 32, N=2**14, r=8, p=1)

    rsa_key = RSA.generate(2048)
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())

    print("[SETUP] keys pre-generated once (ncRNA PBKDF2/sbox seed, AES scrypt, RSA-2048 keypair)")

    schemes = ['Crypto-ncRNA', 'AES', 'RSA']
    results = {
        'meta': {
            'experiment': 'Ciphertext entropy re-measurement (Shannon plug-in + min-entropy)',
            'random_seed': RANDOM_SEED,
            'n_trials': N_TRIALS,
            'data_lengths': DATA_LENGTHS,
            'plaintext_generation': 'fresh random alphanumeric string (ascii_letters + digits) per '
                                    'trial, length = data length; rng = '
                                    'random.Random(20260909 + 100000*scheme_index + 1000*length_index)',
            'protocol_source': 'version1/crypto-ncRNA/Test1.0/test_shang.py (the protocol behind '
                               'main-text Table S6); only deviation: keys/keypair pre-generated '
                               'once instead of per trial (ciphertext entropy is key-independent)',
            'ciphertext_layouts': {
                'Crypto-ncRNA': 'frozen full-config encrypt() output = 8-byte ChaCha20 nonce || '
                                'ciphertext(material) || 32-byte SHA-256 checksum; variant '
                                '"without_checksum" = same output with the trailing checksum removed',
                'AES': 'AES-256-CBC: 16-byte IV || PKCS7-padded ciphertext',
                'RSA': 'RSA-2048 PKCS#1 OAEP, 190-byte payload blocks concatenated (256 B/block)',
            },
            'shannon_estimator': 'plug-in (shuffle) byte-frequency entropy, frozen calculate_entropy',
            'min_entropy_definition': 'H_inf = -log2(max_b p(b)) over pooled byte counts of all 30 '
                                      'trials of a cell',
            'reconciliation_target': 'main-text Table S6 (tab:avg_entropy_si), mean over 30 trials',
            'reconciliation_tolerance': TOLERANCE,
            'frozen_code_path': str(CODE_PATH),
            'frozen_code_sha256': code_sha,
            'frozen_code_access': 'read-only import (stubbed matplotlib.pyplot); file untouched',
            'pre_generated_key_material': {
                'ncrna_sbox_seed': ncrna_sbox_seed,
                'ncrna_seed_sequence': ncrna_seed_sequence,
                'ncrna_salt': ncrna_salt,
                'aes_seed': aes_seed,
                'aes_salt': aes_salt,
            },
            **machine_meta()
        },
        'measurements': {},
        'reconciliation_vs_table_s6': {}
    }

    for si, scheme in enumerate(schemes):
        print(f"\n[{scheme}]")
        results['measurements'][scheme] = {}
        for li, length in enumerate(DATA_LENGTHS):
            rng = random.Random(RANDOM_SEED + 100000 * si + 1000 * li)
            shannon = []
            shannon_nocksum = []
            ct_len = None
            pooled = bytearray()
            for _ in range(N_TRIALS):
                plaintext = make_plaintext(rng, length)
                if scheme == 'Crypto-ncRNA':
                    codons = mod.encode_plaintext_to_codons(plaintext)
                    substituted = mod.substitute_codons(codons, ncrna_matrix)
                    structured, indices_order = mod.apply_rna_secondary_structure(substituted)
                    package = mod.add_checksum(mod.cha_encrypt(''.join(structured), ncrna_key))
                    ct = package
                    ct_nocksum = package[:-32]
                elif scheme == 'AES':
                    cipher = AES.new(aes_key, AES.MODE_CBC)
                    ct = cipher.iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))
                    ct_nocksum = ct
                else:
                    blocks = [rsa_cipher.encrypt(plaintext[i:i + RSA_BLOCK].encode())
                              for i in range(0, len(plaintext), RSA_BLOCK)]
                    ct = b"".join(blocks)
                    ct_nocksum = ct
                ct_len = len(ct)
                shannon.append(shannon_plugin(ct))
                shannon_nocksum.append(shannon_plugin(ct_nocksum))
                pooled.extend(ct)

            entry = {
                'data_length': length,
                'ciphertext_length_bytes': ct_len,
                'shannon': pooled_stats(shannon),
                'shannon_without_checksum': pooled_stats(shannon_nocksum),
                'min_entropy_pooled': min_entropy(bytes(pooled)),
                'pooled_bytes': len(pooled),
            }
            results['measurements'][scheme][str(length)] = entry
            print(f"  {length:6d} B (ct={ct_len:6d} B): Shannon mean={entry['shannon']['mean']:.6f} "
                  f"median={entry['shannon']['median']:.6f} std={entry['shannon']['std']:.6f} | "
                  f"H_inf={entry['min_entropy_pooled']:.4f}")

    # ---- Reconcile against Table S6 ----
    print("\n[RECONCILIATION vs Table S6]")
    max_abs_diff = 0.0
    for si, scheme in enumerate(schemes):
        rows = []
        for li, length in enumerate(DATA_LENGTHS):
            ref = TABLE_S6_REFERENCE[scheme][li]
            got = results['measurements'][scheme][str(length)]['shannon']['mean']
            diff = got - ref
            max_abs_diff = max(max_abs_diff, abs(diff))
            rows.append({
                'data_length': length,
                'table_s6_reference': ref,
                'remeasured_mean': got,
                'abs_diff': abs(diff),
                'within_tolerance': bool(abs(diff) <= TOLERANCE),
                'ciphertext_length_bytes':
                    results['measurements'][scheme][str(length)]['ciphertext_length_bytes'],
            })
            print(f"  {scheme:13s} {length:6d} B: TableS6={ref:.6f}  remeasured={got:.6f}  "
                  f"diff={diff:+.6f}  {'OK' if abs(diff) <= TOLERANCE else 'MISMATCH'}")
        results['reconciliation_vs_table_s6'][scheme] = rows
    results['reconciliation_vs_table_s6']['all_within_tolerance'] = bool(max_abs_diff <= TOLERANCE)
    results['reconciliation_vs_table_s6']['max_abs_diff'] = max_abs_diff
    print(f"\n[RECONCILIATION] max |diff| = {max_abs_diff:.6f}  "
          f"all_within_tolerance={results['reconciliation_vs_table_s6']['all_within_tolerance']}")

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'results_entropy_recheck.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)
