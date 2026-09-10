"""
Shared utility functions for the timing_measure suite.
Purpose: TODO-9 timing-methodology correction and re-measurement.
"""
import os
import sys
import time
import importlib.metadata
import subprocess

# Fixed random seed (reproducibility)
RANDOM_SEED = 20260909

def assert_environment():
    """
    Environment version assertion: keep key dependency versions
    consistent with ENV_PROBE.md.
    """
    import Crypto
    import numpy as np

    pycryptodome_ver = Crypto.__version__
    numpy_ver = np.__version__

    assert pycryptodome_ver == '3.23.0', f"pycryptodome version mismatch: expected 3.23.0, got {pycryptodome_ver}"
    assert numpy_ver == '2.4.6', f"numpy version mismatch: expected 2.4.6, got {numpy_ver}"

    print(f"[ENV] pycryptodome={pycryptodome_ver}, numpy={numpy_ver}")


def set_threading_environment():
    """
    Pin the timing environment to one thread to avoid BLAS
    parallelism variance.
    """
    os.environ['OMP_NUM_THREADS'] = '1'
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    os.environ['MKL_NUM_THREADS'] = '1'
    print(f"[ENV] Threading: OMP/OPENBLAS/MKL_NUM_THREADS=1")


def timeit(func, args=(), kwargs=None, repeats=30, warmup=3):
    """
    Timing helper: warmup + repeats, returns summary statistics.

    Args:
        func: function to be timed
        args: positional arguments
        kwargs: keyword arguments
        repeats: number of repetitions (default 30)
        warmup: number of warm-up runs (default 3)

    Returns:
        dict: {median, mean, std, min, max, all_times}
    """
    if kwargs is None:
        kwargs = {}

    # Warm-up runs
    for _ in range(warmup):
        func(*args, **kwargs)

    # Timed runs
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    import numpy as np
    times_arr = np.array(times)

    return {
        'median': float(np.median(times_arr)),
        'mean': float(np.mean(times_arr)),
        'std': float(np.std(times_arr, ddof=1)),
        'min': float(np.min(times_arr)),
        'max': float(np.max(times_arr)),
        'all_times': times
    }


def machine_meta():
    """
    Record machine metadata: CPU model, core count, system load.
    """
    try:
        # CPU model (C locale to avoid localization)
        cpu_info = subprocess.check_output(
            'LC_ALL=C lscpu | grep "Model name"',
            shell=True, text=True
        ).strip()
        cpu_model = cpu_info.split(':', 1)[1].strip() if ':' in cpu_info else 'Unknown'
    except:
        cpu_model = 'Unknown'

    try:
        nproc = int(subprocess.check_output('nproc', shell=True, text=True).strip())
    except:
        nproc = -1

    try:
        uptime = subprocess.check_output('uptime', shell=True, text=True).strip()
        # Extract load: last three numbers
        loadavg = uptime.split('load average:')[-1].strip() if 'load average:' in uptime else 'N/A'
    except:
        loadavg = 'N/A'

    return {
        'cpu_model': cpu_model,
        'nproc': nproc,
        'loadavg': loadavg,
        'python_version': sys.version.split()[0]
    }


def get_package_version(package_name):
    """
    Get a package version (via importlib.metadata).
    """
    try:
        return importlib.metadata.version(package_name)
    except:
        return 'Unknown'
