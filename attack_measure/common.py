"""Shared helpers for the TODO-8 attack-measurement suite.

Loads the frozen reference implementation (read-only import, file untouched)
with a stubbed matplotlib.pyplot (top-level-import decoupling per TODO.md
TODO-8; pycryptodome/matplotlib ARE importable on this host -- the stub is
for backend/headless decoupling, not a missing library), asserts the pinned
library versions (ENV_PROBE.md 6.8), and fixes the timing environment
(ENV_PROBE.md 6.11).
"""
import hashlib
import importlib.util
import os
import sys
import types
from pathlib import Path

# --- timing environment (ENV_PROBE.md 6.11) ---------------------------------
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

REPO = Path("/lenovofs1/home/wangyq/npj_uncon_comput")
CODE_PATH = REPO / "version2" / "code" / "ncrna" / "ncRNA3.5.py"
OUT_PATH = Path(__file__).resolve().parent / "results.json"
RANDOM_SEED = 20260908

EXPECTED_VERSIONS = {"pycryptodome": "3.23.0", "numpy": "2.4.6"}

# Reference-configuration parameters (the released implementation's own
# demonstration vectors, ncRNA3.5.py L365-366 / L534-537).
DEMO_SEED = "123456789"
DEMO_SEED_SEQUENCE = "ACGU" * 8
DEMO_SALT = b"salt_123"
DEMO_PLAINTEXT = (
    "Hello, World! This is a test of the encryption algorithm based on ncRNA."
)

ACGU_BYTES = frozenset(b"ACGU")
JULIAN_YEAR_S = 31_557_600.0


def assert_environment():
    """Assert pinned versions; return the actual version map."""
    import importlib.metadata as md

    actual = {p: md.version(p) for p in EXPECTED_VERSIONS}
    for pkg, want in EXPECTED_VERSIONS.items():
        if actual[pkg] != want:
            raise RuntimeError(f"{pkg}=={actual[pkg]} != pinned {want}")
    return actual


def load_reference_module():
    """Import the frozen ncRNA3.5.py without touching its file."""
    if not CODE_PATH.is_file():
        raise RuntimeError(f"reference implementation missing: {CODE_PATH}")
    mpl = types.ModuleType("matplotlib")
    pyplot = types.ModuleType("matplotlib.pyplot")
    mpl.pyplot = pyplot
    sys.modules.setdefault("matplotlib", mpl)
    sys.modules.setdefault("matplotlib.pyplot", pyplot)
    spec = importlib.util.spec_from_file_location("ncrna35_frozen", CODE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def code_fingerprint():
    return hashlib.sha256(CODE_PATH.read_bytes()).hexdigest()


def codon_alphabet_valid(material: bytes) -> bool:
    """Adversary-optimal validity check: every byte in {A,C,G,U} (early exit)."""
    for b in material:
        if b not in ACGU_BYTES:
            return False
    return True


def timeit(func, repeats=30, warmup=3):
    """Return timing statistics (seconds) over `repeats` calls."""
    import statistics
    import time

    for _ in range(warmup):
        func()
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        func()
        samples.append(time.perf_counter() - t0)
    return {
        "median_s": statistics.median(samples),
        "mean_s": statistics.fmean(samples),
        "std_s": statistics.stdev(samples),
        "min_s": min(samples),
        "repeats": repeats,
    }


def machine_meta():
    import multiprocessing
    import platform

    cpu = ""
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    return {
        "cpu_model": cpu,
        "nproc": multiprocessing.cpu_count(),
        "loadavg": [round(x, 2) for x in os.getloadavg()],
        "platform": platform.platform(),
    }


def meta_block(versions):
    import platform
    from datetime import datetime, timezone

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "python": platform.python_version(),
        "versions": versions,
        "threads_env": {
            k: os.environ.get(k, "")
            for k in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
        },
        "reference_code": str(CODE_PATH),
        "reference_code_sha256": code_fingerprint(),
        **machine_meta(),
    }
