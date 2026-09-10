"""
Shared utilities for the ablation_measure suite.
Purpose: TODO-10 component ablation experiments
  A1/A2/A3 -- seed layer (KDF seed vs S-box seed) sensitivity
  B1-B5    -- pipeline layer (codon encoding / S-box substitution / fold
              permutation / ChaCha20)
Style follows timing_measure/common.py; the read-only import of the frozen
code follows attack_measure/common.py (stubbed matplotlib.pyplot + sha256
fingerprints).
"""
import hashlib
import importlib.metadata
import importlib.util
import inspect
import os
import random
import subprocess
import sys
import types
from pathlib import Path

# --- Measurement/timing environment: single thread (must take effect before the
# --- first numpy import) ---------------------------------------------------
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'

# Fixed random seed (reproducibility anchor)
RANDOM_SEED = 20260910

REPO = Path("/lenovofs1/home/wangyq/npj_uncon_comput")
CODE_PATH = REPO / "version2" / "code" / "ncrna" / "ncRNA3.5.py"
OUT_PATH = Path(__file__).resolve().parent / "results.json"

EXPECTED_VERSIONS = {"pycryptodome": "3.23.0", "numpy": "2.4.6"}

# --- Reference configuration parameters ------------------------------------
# KDF parameters: identical to the frozen generate_dynamic_key_from_biological_data
KDF_DKLEN = 32
KDF_ITERATIONS = 100000
SALT = b'ablation_salt_01'
SEED_SEQUENCE_LEN = 32          # length of the KDF seed (ACGU string)
ACGU = 'ACGU'
SBOX_SEED_BASE = "123456789"    # baseline S-box seed (v1 demo vector)
SBOX_SEED_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz'
BASE64_ALPHABET_FOR_PLAINTEXT = None  # plaintext alphabet defined in exp2 (ascii_letters+digits)

# Component functions actually called from the frozen implementation (recorded for fingerprints)
COMPONENT_FUNCTIONS = [
    'generate_codon_substitution_matrix',
    'substitute_codons',
    'linear_fold',
    'apply_rna_secondary_structure',
    'inverse_rna_secondary_structure',
    'inverse_substitute_codons',
    'encode_plaintext_to_codons',
    'decode_codons_to_plaintext',
    'generate_dynamic_key_from_biological_data',
    'cha_encrypt',
    'cha_decrypt',
    'calculate_entropy',
]

FROZEN_MODULE_NAME = "ncrna35_frozen_ablation"


def assert_environment():
    """Assert the environment versions: keep key dependencies identical to
    ENV_PROBE.md; return the observed version table"""
    import Crypto
    import numpy as np

    actual = {'pycryptodome': Crypto.__version__, 'numpy': np.__version__}
    for pkg, want in EXPECTED_VERSIONS.items():
        assert actual[pkg] == want, (
            f"{pkg} version mismatch: expected {want}, got {actual[pkg]}"
        )
    print(f"[ENV] pycryptodome={actual['pycryptodome']}, numpy={actual['numpy']}")
    return actual


def set_threading_environment():
    """Pin the timing environment to a single thread to avoid BLAS parallel
    variance (idempotent)"""
    for k in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS'):
        os.environ[k] = '1'
    print("[ENV] Threading: OMP/OPENBLAS/MKL_NUM_THREADS=1")


def load_reference_module():
    """Read-only import of the frozen ncRNA3.5.py (file untouched).

    ncRNA3.5.py imports matplotlib.pyplot at the top, so an empty module stub
    is injected to decouple it (same approach as the attack_measure suite:
    matplotlib is available locally, the stub only serves headless/backend
    decoupling). The module is then loaded from its original path via
    sys.path + importlib.
    """
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


def code_fingerprint():
    """sha256 of the frozen file (read-only, file not modified)"""
    return hashlib.sha256(CODE_PATH.read_bytes()).hexdigest()


def function_fingerprints(mod):
    """Component function fingerprints: sha256 of each function's source text
    (read-only inspect, no file modification)"""
    out = {}
    for name in COMPONENT_FUNCTIONS:
        fn = getattr(mod, name, None)
        if fn is None:
            out[name] = {"sha256": "MISSING", "n_source_lines": 0}
            continue
        try:
            src = inspect.getsource(fn)
            out[name] = {
                "sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
                "n_source_lines": len(src.splitlines()),
            }
        except (OSError, TypeError) as exc:  # pragma: no cover
            out[name] = {"sha256": f"UNAVAILABLE: {exc}", "n_source_lines": 0}
    return out


def machine_meta():
    """Record machine metadata: CPU model (LC_ALL=C lscpu), core count, load average"""
    try:
        cpu_info = subprocess.check_output(
            'LC_ALL=C lscpu | grep "Model name"',
            shell=True, text=True
        ).strip()
        cpu_model = cpu_info.split(':', 1)[1].strip() if ':' in cpu_info else 'Unknown'
    except Exception:
        cpu_model = 'Unknown'

    try:
        nproc = int(subprocess.check_output('nproc', shell=True, text=True).strip())
    except Exception:
        nproc = -1

    try:
        loadavg = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        loadavg = 'N/A'

    return {
        'cpu_model': cpu_model,
        'nproc': nproc,
        'loadavg': loadavg,
        'python_version': sys.version.split()[0],
    }


def pbkdf2(seed_sequence, salt):
    """KDF with the same parameters as the frozen implementation:
    PBKDF2-HMAC-SHA256, dkLen=32, count=1e5"""
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    return PBKDF2(seed_sequence, salt, dkLen=KDF_DKLEN, count=KDF_ITERATIONS,
                  hmac_hash_module=SHA256)


def derive_base_material(rng=None):
    """Baseline material: seed_sequence_base (ACGU, 32 nt) + salt + K_base.

    When rng is not given, a fresh Random(RANDOM_SEED) is created; when it is
    given, the same rng stream is reused (callers may keep drawing variants
    from it, preserving the "single rng stream" convention).
    """
    if rng is None:
        rng = random.Random(RANDOM_SEED)
    seed_sequence_base = ''.join(rng.choice(ACGU) for _ in range(SEED_SEQUENCE_LEN))
    k_base = pbkdf2(seed_sequence_base, SALT)
    return seed_sequence_base, SALT, k_base, rng


def single_base_substitution(rng, seq, alphabet):
    """Single-character substitution variant (the minimal natural perturbation
    shared by A1/A3/B3).

    The same rng stream picks a position pos in [0, len) and a new character
    new in alphabet with new != original. Returns (variant, pos, orig, new).
    """
    pos = rng.randrange(len(seq))
    orig = seq[pos]
    new = rng.choice(alphabet)
    while new == orig:
        new = rng.choice(alphabet)
    return seq[:pos] + new + seq[pos + 1:], pos, orig, new


def bit_flip_ratio(bytes_a, bytes_b):
    """Bit flip ratio of two equal-length byte strings (Hamming distance / total bits)"""
    assert len(bytes_a) == len(bytes_b), (
        f"length mismatch for bit flip ratio: {len(bytes_a)} vs {len(bytes_b)}"
    )
    n_bits = 8 * len(bytes_a)
    if n_bits == 0:
        return 0.0
    xor = int.from_bytes(bytes_a, 'big') ^ int.from_bytes(bytes_b, 'big')
    return xor.bit_count() / n_bits


def stats(values, unit=None):
    """Summary statistics: mean/std(ddof=1)/min/max + all_values (raw value array so
    results can be recomputed)"""
    import numpy as np
    arr = np.asarray(list(values), dtype=float)
    if arr.size == 0:
        raise ValueError("stats() on empty collection")
    out = {
        'n': int(arr.size),
        'mean': float(arr.mean()),
        'std': float(arr.std(ddof=1)) if arr.size > 1 else 0.0,
        'min': float(arr.min()),
        'max': float(arr.max()),
        'all_values': [float(v) for v in arr],
    }
    if unit is not None:
        out['unit'] = unit
    return out


def meta_block(versions, extra=None):
    """Top-level meta for results.json: timestamp, machine, versions, seed,
    fingerprints, protocol declarations"""
    from datetime import datetime, timezone

    meta = {
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'purpose': 'TODO-10 component ablation (seed layer A1-A3, pipeline layer B1-B5)',
        'random_seed': RANDOM_SEED,
        'std_ddof': 1,
        'threads_env': {
            k: os.environ.get(k, '')
            for k in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS')
        },
        'versions': versions,
        **machine_meta(),
        'frozen_code_path': str(CODE_PATH),
        'frozen_code_sha256': code_fingerprint(),
        'frozen_code_access': 'read-only import (stubbed matplotlib.pyplot); file untouched',
        'component_function_sha256': None,   # filled in by run_all
        'nonce_policy': None,                # filled in by run_all
        'trial_count_declaration': None,     # filled in by run_all
    }
    if extra:
        meta.update(extra)
    return meta
