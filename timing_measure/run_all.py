"""
Orchestrator: run all timing experiments and consolidate the results.
Purpose: TODO-9 timing-methodology correction and re-measurement.
"""
import os
import sys
import json
import subprocess
from datetime import datetime

def run_experiment(script_name, description):
    """
    Run a single experiment script.
    """
    print(f"\n{'='*70}")
    print(f"Running: {description}")
    print(f"Script:  {script_name}")
    print('='*70)

    script_path = os.path.join(os.path.dirname(__file__), script_name)
    python_exe = os.path.expanduser('~/miniconda3/envs/claude/bin/python')

    result = subprocess.run(
        [python_exe, script_path],
        cwd=os.path.dirname(__file__),
        capture_output=False,
        text=True
    )

    if result.returncode != 0:
        print(f"\n[ERROR] {script_name} failed, exit code: {result.returncode}")
        sys.exit(1)

    print(f"\n[DONE] {description}")
    return result.returncode == 0

def main():
    print("="*70)
    print("TODO-9 timing re-measurement suite - orchestrator")
    print(f"Time: {datetime.now().isoformat()}")
    print("="*70)

    experiments = [
        ('exp1_kdf_measurement.py', 'Exp 1: KDF key establishment cost'),
        ('exp2_per_message_operations.py', 'Exp 2: per-message encryption/decryption'),
        ('exp3_rsa_keygen.py', 'Exp 3: RSA-2048 key pair generation'),
        ('exp4_mlkem768_baseline.py', 'Exp 4: ML-KEM-768 dual-implementation baseline'),
    ]

    # Run all experiments sequentially
    for script, desc in experiments:
        success = run_experiment(script, desc)
        if not success:
            print(f"\n[FATAL] {desc} failed, aborting")
            sys.exit(1)

    # Consolidate results
    print("\n" + "="*70)
    print("Consolidating result files")
    print("="*70)

    result_files = [
        'exp1_results.json',
        'exp2_results.json',
        'exp3_results.json',
        'exp4_results.json'
    ]

    consolidated = {
        'meta': {
            'suite': 'TODO-9 Timing Remeasurement',
            'timestamp': datetime.now().isoformat(),
            'experiments': len(result_files)
        },
        'results': {}
    }

    for rf in result_files:
        rf_path = os.path.join(os.path.dirname(__file__), rf)
        if os.path.exists(rf_path):
            with open(rf_path, 'r') as f:
                data = json.load(f)
                exp_key = rf.replace('_results.json', '')
                consolidated['results'][exp_key] = data
            print(f"  ✓ {rf}")
        else:
            print(f"  ✗ {rf} not found")

    # Save consolidated results
    output_path = os.path.join(os.path.dirname(__file__), 'results_all.json')
    with open(output_path, 'w') as f:
        json.dump(consolidated, f, indent=2)

    print(f"\n[CONSOLIDATED] {output_path}")
    print("\n" + "="*70)
    print("All experiments finished")
    print("="*70)

if __name__ == '__main__':
    main()
