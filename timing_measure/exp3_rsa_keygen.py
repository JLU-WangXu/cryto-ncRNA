"""
Experiment 3: RSA-2048 key pair generation cost.
Goal: measure the cost of RSA.generate(2048) for comparison with
literature/specification figures.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(__file__))
from common import assert_environment, set_threading_environment, timeit, machine_meta, RANDOM_SEED

import numpy as np
from Crypto.PublicKey import RSA

def main():
    print("=" * 60)
    print("Experiment 3: RSA-2048 key pair generation cost")
    print("=" * 60)

    set_threading_environment()
    assert_environment()

    np.random.seed(RANDOM_SEED)

    results = {
        'meta': {
            'experiment': 'RSA-2048 Key Pair Generation Cost',
            'random_seed': RANDOM_SEED,
            'repeats': 30,
            'warmup': 3,
            **machine_meta()
        },
        'keygen_measurement': {}
    }

    print("\n[1] RSA.generate(2048) measurement")

    def rsa_keygen():
        RSA.generate(2048)

    stats = timeit(rsa_keygen, repeats=30, warmup=3)

    print(f"  median: {stats['median']:.4f} s ({stats['median']*1000:.2f} ms)")
    print(f"  mean:   {stats['mean']:.4f} s ± {stats['std']:.4f} s")
    print(f"  range:  [{stats['min']:.4f}, {stats['max']:.4f}] s")

    results['keygen_measurement']['RSA_2048'] = {
        'algorithm': 'RSA-2048',
        'key_size_bits': 2048,
        'stats': stats,
        'note': 'Measured via Crypto.PublicKey.RSA.generate(2048) from pycryptodome 3.23.0'
    }

    # ========== Save results ==========
    output_path = os.path.join(os.path.dirname(__file__), 'exp3_results.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[OUTPUT] results saved to: {output_path}")
    print("=" * 60)

if __name__ == '__main__':
    main()
