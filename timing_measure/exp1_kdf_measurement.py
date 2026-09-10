"""
Experiment 1: KDF cost measurement (key establishment stage).
Goal: PBKDF2 (10^4/10^5/6x10^5) + scrypt (N=2^14), dual implementation
(pycryptodome vs hashlib).
"""
import os
import sys
import hashlib
import json

# Make common.py importable
sys.path.insert(0, os.path.dirname(__file__))
from common import assert_environment, set_threading_environment, timeit, machine_meta, RANDOM_SEED

import numpy as np
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Hash import SHA256

def main():
    print("=" * 60)
    print("Experiment 1: KDF key establishment cost measurement")
    print("=" * 60)

    set_threading_environment()
    assert_environment()

    np.random.seed(RANDOM_SEED)

    # Fixed input parameters
    PASSWORD = b"test_password_for_kdf_benchmark"
    SALT = b"fixed_salt_16byt"
    DKLEN = 32

    results = {
        'meta': {
            'experiment': 'KDF Key Establishment Cost',
            'random_seed': RANDOM_SEED,
            'repeats': 30,
            'warmup': 3,
            **machine_meta()
        },
        'kdf_measurements': {}
    }

    # ========== PBKDF2 measurement ==========
    print("\n[1] PBKDF2-HMAC-SHA256 measurement")

    for iterations in [10000, 100000, 600000]:
        print(f"\n  iterations: {iterations}")

        # pycryptodome implementation
        def pbkdf2_pycryptodome():
            PBKDF2(PASSWORD, SALT, dkLen=DKLEN, count=iterations, hmac_hash_module=SHA256)

        stats_pyc = timeit(pbkdf2_pycryptodome, repeats=30, warmup=3)
        print(f"    pycryptodome: {stats_pyc['median']*1000:.2f} ms (median)")

        # hashlib implementation (OpenSSL backend)
        def pbkdf2_hashlib():
            hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, iterations, dklen=DKLEN)

        stats_hl = timeit(pbkdf2_hashlib, repeats=30, warmup=3)
        print(f"    hashlib:      {stats_hl['median']*1000:.2f} ms (median)")

        speedup = stats_pyc['median'] / stats_hl['median']
        print(f"    speed ratio (pycryptodome/hashlib): {speedup:.2f}x")

        results['kdf_measurements'][f'PBKDF2_iter_{iterations}'] = {
            'iterations': iterations,
            'algorithm': 'PBKDF2-HMAC-SHA256',
            'pycryptodome': stats_pyc,
            'hashlib': stats_hl,
            'speedup_ratio': float(speedup)
        }

    # ========== scrypt measurement ==========
    print("\n[2] scrypt measurement (N=2^14, r=8, p=1)")

    N = 2**14
    r = 8
    p = 1

    # pycryptodome implementation
    def scrypt_pycryptodome():
        scrypt(PASSWORD, SALT, key_len=DKLEN, N=N, r=r, p=p)

    stats_pyc_scrypt = timeit(scrypt_pycryptodome, repeats=30, warmup=3)
    print(f"  pycryptodome: {stats_pyc_scrypt['median']*1000:.2f} ms (median)")

    # hashlib implementation
    def scrypt_hashlib():
        hashlib.scrypt(PASSWORD, salt=SALT, n=N, r=r, p=p, dklen=DKLEN)

    stats_hl_scrypt = timeit(scrypt_hashlib, repeats=30, warmup=3)
    print(f"  hashlib:      {stats_hl_scrypt['median']*1000:.2f} ms (median)")

    speedup_scrypt = stats_pyc_scrypt['median'] / stats_hl_scrypt['median']
    print(f"  speed ratio (pycryptodome/hashlib): {speedup_scrypt:.2f}x")

    results['kdf_measurements']['scrypt_N_2_14'] = {
        'N': N,
        'r': r,
        'p': p,
        'algorithm': 'scrypt',
        'pycryptodome': stats_pyc_scrypt,
        'hashlib': stats_hl_scrypt,
        'speedup_ratio': float(speedup_scrypt)
    }

    # ========== Save results ==========
    output_path = os.path.join(os.path.dirname(__file__), 'exp1_results.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)

if __name__ == '__main__':
    main()
