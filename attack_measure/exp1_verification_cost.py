"""Experiment 1 - per-guess verification cost decomposition (TODO-8 item 1).

Measures, against the frozen reference implementation (v1):
  - PBKDF2-HMAC-SHA256 (1e5 iterations, dkLen=32): the pycryptodome backend
    actually used by the implementation, and the OpenSSL (hashlib) backend as
    the attacker-optimized bound,
  - ChaCha20 decryption of the reference payload,
  - the nucleotide-alphabet validity check,
  - the composed reject path (KDF -> stream-cipher decryption -> validity),
  - the O(n) structure-prediction pass at 32/128/1024 nt,
  - the full honest decrypt() pipeline (reference path),
and extrapolates exhaustive-search costs for 32/64/128-nt seed spaces.

Run:  ~/miniconda3/envs/claude/bin/python exp1_verification_cost.py
"""
import hashlib
import json

from Crypto.Cipher import ChaCha20

from common import (
    DEMO_PLAINTEXT,
    DEMO_SALT,
    DEMO_SEED,
    DEMO_SEED_SEQUENCE,
    JULIAN_YEAR_S,
    codon_alphabet_valid,
    load_reference_module,
    timeit,
)


def run(mod):
    import random

    rng = random.Random(20260908)
    fold_inputs = {
        str(n): "".join(rng.choice("ACGU") for _ in range(n)) for n in (32, 128, 1024)
    }

    # One reference encryption to obtain a realistic payload.
    encrypted, sub_matrix, indices_order = mod.encrypt(
        DEMO_PLAINTEXT, DEMO_SEED, DEMO_SEED_SEQUENCE, DEMO_SALT
    )
    payload = encrypted[:-32]
    nonce, ct = payload[:8], payload[8:]
    key = mod.generate_dynamic_key_from_biological_data(DEMO_SEED_SEQUENCE, DEMO_SALT)
    material = ChaCha20.new(key=key, nonce=nonce).decrypt(ct)

    # --- component measurements -------------------------------------------
    kdf_pycrypto = timeit(
        lambda: mod.generate_dynamic_key_from_biological_data(
            DEMO_SEED_SEQUENCE, DEMO_SALT
        )
    )
    kdf_hashlib = timeit(
        lambda: hashlib.pbkdf2_hmac(
            "sha256", DEMO_SEED_SEQUENCE.encode(), DEMO_SALT, 100_000, dklen=32
        )
    )
    chacha_dec = timeit(lambda: ChaCha20.new(key=key, nonce=nonce).decrypt(ct))
    validity = timeit(lambda: codon_alphabet_valid(material))

    def guess_path_impl():
        k = mod.generate_dynamic_key_from_biological_data(DEMO_SEED_SEQUENCE, DEMO_SALT)
        m = ChaCha20.new(key=k, nonce=nonce).decrypt(ct)
        return codon_alphabet_valid(m)

    def guess_path_openssl():
        k = hashlib.pbkdf2_hmac(
            "sha256", DEMO_SEED_SEQUENCE.encode(), DEMO_SALT, 100_000, dklen=32
        )
        m = ChaCha20.new(key=k, nonce=nonce).decrypt(ct)
        return codon_alphabet_valid(m)

    guess_impl = timeit(guess_path_impl)
    guess_ossl = timeit(guess_path_openssl)
    full_decrypt = timeit(
        lambda: mod.decrypt(
            encrypted, DEMO_SEED, DEMO_SEED_SEQUENCE, DEMO_SALT, sub_matrix, indices_order
        )
    )
    fold_scan = {
        n: timeit(lambda s=s: mod.linear_fold(s)) for n, s in fold_inputs.items()
    }

    kdf_fraction = kdf_pycrypto["median_s"] / guess_impl["median_s"]
    rate_impl = 1.0 / guess_impl["median_s"]
    rate_ossl = 1.0 / guess_ossl["median_s"]

    # --- exhaustive-search extrapolation -----------------------------------
    def space(bits, per_guess_s):
        candidates = float(2) ** bits
        core_years = candidates * per_guess_s / JULIAN_YEAR_S
        return {
            "bits": bits,
            "candidates": candidates,
            "core_years_single_core": core_years,
            "wall_years_at_1e4_cores": core_years / 1e4,
            "wall_years_at_1e6_cores": core_years / 1e6,
        }

    exhaustive = {
        f"{L}nt": {
            **space(2 * L, guess_impl["median_s"]),
            "core_years_openssl_bound": space(2 * L, guess_ossl["median_s"])[
                "core_years_single_core"
            ],
        }
        for L in (32, 64, 128)
    }

    return {
        "payload_bytes": len(payload),
        "material_bytes": len(material),
        "components": {
            "kdf_pycryptodome_1e5": kdf_pycrypto,
            "kdf_hashlib_1e5": kdf_hashlib,
            "chacha20_decrypt": chacha_dec,
            "validity_check": validity,
        },
        "composed": {
            "guess_path_implementation": guess_impl,
            "guess_path_openssl_bound": guess_ossl,
            "full_decrypt_pipeline": full_decrypt,
        },
        "kdf_fraction_of_guess_path": kdf_fraction,
        "rates_per_core_cands_per_s": {
            "implementation": rate_impl,
            "openssl_bound": rate_ossl,
            "openssl_speedup_factor": rate_ossl / rate_impl,
        },
        "structure_prediction_pass_s": fold_scan,
        "exhaustive_extrapolation_linear": exhaustive,
        "extrapolation_note": (
            "linear extrapolation from the measured single-core reject path; "
            "Julian year = 31557600 s; parallelism rows assume perfect scaling"
        ),
    }


if __name__ == "__main__":
    mod = load_reference_module()
    print(json.dumps(run(mod), indent=2))
