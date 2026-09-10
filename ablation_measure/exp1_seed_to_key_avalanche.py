"""
Experiment 1: seed-layer ablation (TODO-10)
  A1  single-base substitution of the KDF seed (seed_sequence, ACGU) ->
      avalanche of the 32-byte dynamic key
  A3  single-round SHA-256 control (same variant list,
      hashlib.sha256(variant+salt)) -> 128-bit flip ratio
  A2  single-character substitution of the S-box seed (string) -> change in the
      codon permutation matrix + proof that the S-box seed is decoupled from
      the KDF seed
"""
import hashlib
import json
import random
import sys
import time

from common import (
    ACGU,
    KDF_DKLEN,
    KDF_ITERATIONS,
    RANDOM_SEED,
    SALT,
    SEED_SEQUENCE_LEN,
    SBOX_SEED_ALPHABET,
    SBOX_SEED_BASE,
    bit_flip_ratio,
    derive_base_material,
    load_reference_module,
    pbkdf2,
    single_base_substitution,
    stats,
)

N_TRIALS = 2000
N_DECOUPLE_SAMPLES = 30
# rng stream derivation rules (recorded in results for reproducibility)
RNG_RULE = {
    'base_and_A1_A3_variants': f"random.Random({RANDOM_SEED}) -- generates seed_sequence_base "
                               f"(32 ACGU) first, then the same rng stream yields "
                               f"{N_TRIALS} consecutive single-base-substitution variants",
    'A2_seed_variants': f"random.Random({RANDOM_SEED} + 1), alphabet={SBOX_SEED_ALPHABET}",
    'A2_decouple_sample': f"random.Random({RANDOM_SEED} + 2).sample(range({N_TRIALS}), {N_DECOUPLE_SAMPLES})",
}
# Sanity band (TODO-10 convention): ideal avalanche mean for a 128-bit output is ~0.5
AVALANCHE_BAND = (0.47, 0.53)


def _progress(done, total, t0, tag):
    el = time.perf_counter() - t0
    eta = el / done * (total - done) if done else 0.0
    print(f"    [{tag}] {done}/{total}  elapsed={el:6.1f}s  eta={eta:6.1f}s", flush=True)


def run(mod):
    print("=" * 60)
    print("Experiment 1: seed -> key avalanche / decoupling (A1 / A2 / A3)")
    print("=" * 60)

    rng = random.Random(RANDOM_SEED)
    seed_sequence_base, salt, k_base, rng = derive_base_material(rng)
    h_base = hashlib.sha256(seed_sequence_base.encode('utf-8') + salt).digest()

    print(f"[setup] seed_sequence_base = {seed_sequence_base}")
    print(f"[setup] salt                = {salt.decode()!r}")
    print(f"[setup] K_base              = {k_base.hex()}")
    print(f"[setup] H_base(sha256)      = {h_base.hex()}")

    # ---- Variant list (A1/A3 share the same list for paired comparison;
    # ---- single-base substitution convention) ----------------------------
    variants = []
    for _ in range(N_TRIALS):
        variant, pos, orig, new = single_base_substitution(rng, seed_sequence_base, ACGU)
        # Sanity check: differs from the baseline at exactly one position
        assert sum(a != b for a, b in zip(variant, seed_sequence_base)) == 1
        assert variant != seed_sequence_base and new != orig
        variants.append(variant)
    print(f"[setup] {N_TRIALS} single-base-substitution variants generated")

    # ---- A1: KDF avalanche ----------------------------------------------
    print(f"[A1] PBKDF2-HMAC-SHA256 (dkLen={KDF_DKLEN}, count={KDF_ITERATIONS}) avalanche")
    a1_values = []
    t0 = time.perf_counter()
    pbkdf2_calls = 1  # K_base
    for i, variant in enumerate(variants, start=1):
        k_i = pbkdf2(variant, salt)
        pbkdf2_calls += 1
        a1_values.append(bit_flip_ratio(k_base, k_i))
        if i % 500 == 0:
            _progress(i, N_TRIALS, t0, "A1 PBKDF2")
    a1 = stats(a1_values, unit='fraction of 128 key bits flipped')
    print(f"[A1] mean={a1['mean']:.4f} std={a1['std']:.4f} "
          f"min={a1['min']:.4f} max={a1['max']:.4f}")

    # ---- A3: single-round SHA-256 control (same variant list) ------------
    print("[A3] single-round SHA-256(variant.encode('utf-8') + salt) control")
    a3_values = [
        bit_flip_ratio(h_base, hashlib.sha256(v.encode('utf-8') + salt).digest())
        for v in variants
    ]
    a3 = stats(a3_values, unit='fraction of 128 digest bits flipped')
    print(f"[A3] mean={a3['mean']:.4f} std={a3['std']:.4f} "
          f"min={a3['min']:.4f} max={a3['max']:.4f}")

    # ---- A2: S-box seed ablation + decoupling from the KDF seed ----------
    print(f"[A2] S-box seed ablation (base seed = {SBOX_SEED_BASE!r})")
    m_base = mod.generate_codon_substitution_matrix(SBOX_SEED_BASE)
    assert len(m_base) == 64

    rng_sbox = random.Random(RANDOM_SEED + 1)
    diff_fracs = []
    fixed_points = []
    variant_seeds = []
    for _ in range(N_TRIALS):
        seed_i, _pos, _orig, new = single_base_substitution(
            rng_sbox, SBOX_SEED_BASE, SBOX_SEED_ALPHABET
        )
        assert seed_i != SBOX_SEED_BASE and new != SBOX_SEED_BASE[_pos]
        m_i = mod.generate_codon_substitution_matrix(seed_i)
        assert len(m_i) == 64 and set(m_i) == set(m_base)
        diff_fracs.append(sum(1 for k in m_base if m_i[k] != m_base[k]) / 64.0)
        fixed_points.append(sum(1 for k, v in m_i.items() if k == v))
        variant_seeds.append(seed_i)
    diff_stat = stats(diff_fracs, unit='fraction of the 64 codon mappings that differ from M_base')
    fp_stat = stats(fixed_points, unit='count of fixed points (k == v) out of 64')
    print(f"[A2] diff/64 mean={diff_stat['mean']:.4f} std={diff_stat['std']:.4f} "
          f"min={diff_stat['min']:.4f} max={diff_stat['max']:.4f}")
    print(f"[A2] fixed points mean={fp_stat['mean']:.4f} std={fp_stat['std']:.4f} "
          f"min={fp_stat['min']:.0f} max={fp_stat['max']:.0f}")

    # Decoupling check: vary the S-box seed with the KDF seed fixed ->
    # the dynamic key must be identical byte-for-byte
    rng_dec = random.Random(RANDOM_SEED + 2)
    sample_idx = sorted(rng_dec.sample(range(N_TRIALS), N_DECOUPLE_SAMPLES))
    identical = 0
    for j in sample_idx:
        k_i2 = pbkdf2(seed_sequence_base, salt)
        pbkdf2_calls += 1
        assert k_i2 == k_base, (
            f"decoupling violated for S-box seed variant {variant_seeds[j]!r}"
        )
        identical += 1
    assert identical == N_DECOUPLE_SAMPLES, (
        f"identical_count={identical} != {N_DECOUPLE_SAMPLES}"
    )
    print(f"[A2] decoupling: {identical}/{N_DECOUPLE_SAMPLES} sampled S-box seed variants "
          f"-> K identical to K_base byte-for-byte")

    # ---- Sanity checks (recorded only; not hard failures, except the
    # ---- decoupling assertion) -------------------------------------------
    band_lo, band_hi = AVALANCHE_BAND
    sanity = {
        'A1_mean_in_band_0.47_0.53': bool(band_lo <= a1['mean'] <= band_hi),
        'A3_mean_in_band_0.47_0.53': bool(band_lo <= a3['mean'] <= band_hi),
        'A2_diff_fraction_gt_0.9': bool(diff_stat['min'] > 0.9),
        'A2_identical_count_30': identical == N_DECOUPLE_SAMPLES,
    }
    print(f"[sanity] {json.dumps(sanity)}")

    return {
        'experiment': 'exp1_seed_to_key_avalanche',
        'setup': {
            'seed_sequence_base': seed_sequence_base,
            'seed_sequence_len_nt': SEED_SEQUENCE_LEN,
            'salt': salt.decode('utf-8', 'backslashreplace'),
            'kdf': f'PBKDF2-HMAC-SHA256, dkLen={KDF_DKLEN}, count={KDF_ITERATIONS}',
            'K_base_hex': k_base.hex(),
            'H_base_hex': h_base.hex(),
            'sbox_seed_base': SBOX_SEED_BASE,
            'sbox_seed_alphabet': SBOX_SEED_ALPHABET,
            'n_trials': N_TRIALS,
            'variant_rule': 'single-base substitution: same rng stream picks pos in [0,32) '
                            'and new base in ACGU with new != original (ACGU is the native '
                            'alphabet, so one base is the smallest natural perturbation)',
            'A1_A3_share_variant_list': True,
            'rng_derivation': RNG_RULE,
        },
        'A1_kdf_avalanche': {
            'description': 'K_i = PBKDF2(variant, salt); flip ratio vs K_base over 128 bits',
            'stat': a1,
            'sanity_band': list(AVALANCHE_BAND),
        },
        'A3_sha256_single_round': {
            'description': 'H_i = sha256(variant.encode("utf-8") + salt), one round; '
                           'flip ratio vs H_base over 128 bits (same variant list as A1)',
            'stat': a3,
            'sanity_band': list(AVALANCHE_BAND),
        },
        'A2_sbox_seed_ablation': {
            'description': 'seed_i = single-char substitution in SBOX_SEED_BASE; '
                           'M_i = generate_codon_substitution_matrix(seed_i)',
            'n_trials': N_TRIALS,
            'diff_fraction_vs_M_base': diff_stat,
            'fixed_point_count': fp_stat,
            'decoupling_check': {
                'description': 'K_i2 = PBKDF2(seed_sequence_base, salt) recomputed for sampled '
                               'S-box seed variants; must equal K_base byte-for-byte',
                'n_sampled': N_DECOUPLE_SAMPLES,
                'sample_indices': sample_idx,
                'sample_variant_seeds': [variant_seeds[j] for j in sample_idx],
                'identical_count': identical,
                'all_identical': identical == N_DECOUPLE_SAMPLES,
            },
        },
        'pbkdf2_call_count': pbkdf2_calls,
        'sanity_checks': sanity,
        'all_sanity_pass': all(sanity.values()),
    }


if __name__ == '__main__':
    _mod = load_reference_module()
    print(json.dumps(run(_mod), indent=2)[:2000])
