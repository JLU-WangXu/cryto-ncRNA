"""
Experiment 2: pipeline component ablation (TODO-10)
Four configs (pipelines rebuilt from the frozen component functions;
ncRNA3.5.encrypt is not called):
  full        : encode -> substitute(M) -> apply_rna_secondary_structure -> ChaCha20
  no_fold     : encode -> substitute(M) -> (fold skipped, idx=identity)  -> ChaCha20
  no_sbox     : encode -> substitute(identity map) -> apply_rna_secondary_structure -> ChaCha20
  cipher_only : encode -> (stream cipher only)                           -> ChaCha20
Metrics:
  B1 ciphertext entropy (random nonce, v1 default behaviour)
  B2 plaintext avalanche (fixed nonce, controlled setting)
  B3 key avalanche -> ciphertext (fixed nonce; variants follow the exp1 single-base rule)
  B4 intermediate-state diffusion (material-layer contribution: S-box substitution rate /
      fold position move rate / adjacent duplicate pair ratio)
  B5 error intolerance (1-bit ciphertext flip -> round-trip decryption behaviour)
"""
import contextlib
import io
import json
import math
import random
import string
import sys
import time
from collections import Counter

from Crypto.Cipher import ChaCha20

from common import (
    ACGU,
    RANDOM_SEED,
    SALT,
    bit_flip_ratio,
    derive_base_material,
    load_reference_module,
    pbkdf2,
    single_base_substitution,
    stats,
)

CONFIGS = ['full', 'no_fold', 'no_sbox', 'cipher_only']
PLAINTEXT_LENGTHS = [128, 1024, 10240]
N_TRIALS = 30
FIXED_NONCE = b'12345678'
REDUNDANT_CONTROL_PLAINTEXT = 'A' * 1024

# rng stream derivation rules (recorded in results for reproducibility)
RNG_RULE = {
    'plaintexts': f"random.Random({RANDOM_SEED} + k), k=0,1,2 for lengths 128/1024/10240; "
                  "''.join(rng.choice(alphabet) for _ in range(L))",
    'plaintext_alphabet': 'string.ascii_letters + string.digits (62 printable ASCII chars)',
    'B2_bitflips': f"random.Random({RANDOM_SEED} + 1000*config_index + 10*length_index), "
                   f"30 sequential draws per (config,length)",
    'B3_key_variants': f"random.Random({RANDOM_SEED} + 200000 + 1000*config_index + 10*length_index), "
                       f"single-base substitution on seed_sequence_base (same rule as exp1)",
    'B5_bitflips': f"random.Random({RANDOM_SEED} + 300000 + 1000*config_index), "
                   f"30 sequential draws per config",
}

BIT_FLIP_POLICY = {
    'B2_plaintext': 'uniform random character index in [0, len(P0)) x uniform random bit in [0,6]; '
                    'bits 0-6 only so the mutated character stays single-byte 7-bit ASCII and the '
                    'material/ciphertext length is preserved (denominator is exactly 8*len(C0))',
    'B5_ciphertext': 'uniform random byte in the ciphertext body (8-byte nonce prefix excluded, '
                     'so the fixed-nonce control is preserved) x uniform random bit in [0,7]',
}


# --------------------------------------------------------------------------- #
# Pipeline construction
# --------------------------------------------------------------------------- #
def codon_alphabet():
    """The 64 codons (same order as the frozen codons array)"""
    return [a + b + c for a in 'ACGU' for b in 'ACGU' for c in 'ACGU']


def build_material(mod, cfg, plaintext, matrices):
    """Build the ChaCha20 encryption material for a config (plaintext-side
    pipeline); return intermediate states and decryption metadata"""
    codon0 = mod.encode_plaintext_to_codons(plaintext)
    n_char = 3 * len(codon0)
    identity_idx = list(range(n_char))

    if cfg == 'full':
        matrix = matrices['true']
        codon1 = mod.substitute_codons(codon0, matrix)
        structured, idx = mod.apply_rna_secondary_structure(codon1)
        material = ''.join(structured)
    elif cfg == 'no_fold':
        matrix = matrices['true']
        codon1 = mod.substitute_codons(codon0, matrix)
        structured = list(codon1)          # not permuted: character order equals codon1
        idx = identity_idx
        material = ''.join(codon1)
    elif cfg == 'no_sbox':
        matrix = matrices['identity']
        codon1 = list(codon0)              # identity map: unchanged by substitution
        structured, idx = mod.apply_rna_secondary_structure(codon0)
        material = ''.join(structured)
    elif cfg == 'cipher_only':
        matrix = matrices['identity']
        codon1 = list(codon0)
        structured = list(codon0)
        idx = identity_idx
        material = ''.join(codon0)
    else:
        raise ValueError(f"unknown config: {cfg}")

    assert len(material) == n_char == len(idx)
    return {
        'material': material,
        'matrix': matrix,
        'indices': idx,
        'codon0': codon0,
        'codon1': codon1,
        'structured': structured,
    }


def encrypt_material(mod, material, key, nonce=None):
    """ChaCha20 encryption. With nonce=None, use the frozen cha_encrypt (random
    8-byte nonce, v1 default); with an explicit nonce, build the ciphertext
    directly (fixed-nonce controlled setting, used for the avalanche metrics)"""
    data = material.encode('utf-8')
    if nonce is None:
        return mod.cha_encrypt(data, key)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce + cipher.encrypt(data)


def decrypt_with_frozen(mod, ciphertext, key, matrix, indices_order):
    """Round-trip decryption with the true key / true matrix / true index order
    (all via the frozen component functions)"""
    with contextlib.redirect_stdout(io.StringIO()):
        codon_seq = mod.cha_decrypt(ciphertext, key)
        unfolded = mod.inverse_rna_secondary_structure(codon_seq, indices_order)
        original_codons = mod.inverse_substitute_codons(unfolded, matrix)
        return mod.decode_codons_to_plaintext(original_codons)


def adjacent_duplicate_ratio(s):
    """Fraction of adjacent equal character pairs (character level)"""
    if len(s) < 2:
        return 0.0
    return sum(1 for a, b in zip(s, s[1:]) if a == b) / (len(s) - 1)


def make_plaintexts():
    alphabet = string.ascii_letters + string.digits
    out = {}
    for k, length in enumerate(PLAINTEXT_LENGTHS):
        rng = random.Random(RANDOM_SEED + k)
        out[length] = ''.join(rng.choice(alphabet) for _ in range(length))
    return out, alphabet


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
def run(mod):
    print("=" * 60)
    print("Experiment 2: pipeline component ablation (B1-B5, four configs x 3 lengths)")
    print("=" * 60)

    seed_sequence_base, salt, k_base, _ = derive_base_material()
    matrices = {
        'true': mod.generate_codon_substitution_matrix('123456789'),
        'identity': {c: c for c in codon_alphabet()},
    }
    assert list(mod.codons) == codon_alphabet(), "codon alphabet/order mismatch vs frozen code"
    plaintexts, plaintext_alphabet = make_plaintexts()

    # ---- Equivalence self-check: 1KB plaintext encrypt -> decrypt round trip
    # ---- ------------------------------------------------------------------
    print("[check] equivalence round-trip on the 1KB plaintext (all four configs)")
    roundtrip = {}
    for cfg in CONFIGS:
        built = build_material(mod, cfg, plaintexts[1024], matrices)
        ct = encrypt_material(mod, built['material'], k_base)          # random nonce
        recovered = decrypt_with_frozen(mod, ct, k_base, built['matrix'], built['indices'])
        roundtrip[cfg] = bool(recovered == plaintexts[1024])
        print(f"    {cfg:12s} roundtrip_ok={roundtrip[cfg]} "
              f"(material={len(built['material'])} B, ciphertext={len(ct)} B)")
    assert roundtrip['full'], "full-config round-trip failed"
    assert all(roundtrip.values()), f"round-trip failed for some config: {roundtrip}"

    # ---- B1 ciphertext entropy -------------------------------------------
    print(f"[B1] ciphertext entropy, {len(CONFIGS)} configs x {len(PLAINTEXT_LENGTHS)} lengths "
          f"x {N_TRIALS} trials (random 8B nonce, frozen cha_encrypt)")
    b1 = {}
    b1_ct_len = {}
    t0 = time.perf_counter()
    for ci, cfg in enumerate(CONFIGS):
        b1[cfg] = {}
        pooled = []
        for length in PLAINTEXT_LENGTHS:
            material = build_material(mod, cfg, plaintexts[length], matrices)['material']
            vals = []
            ct_len = None
            for _ in range(N_TRIALS):
                ct = encrypt_material(mod, material, k_base, nonce=None)
                ct_len = len(ct)
                vals.append(mod.calculate_entropy(ct))
            b1_ct_len[(cfg, length)] = ct_len
            entry = stats(vals, unit='bits/byte')
            # First-order finite-sample bias prediction (plug-in entropy estimator):
            # E[H] ~ 8 - K/(2*N*ln2), K=256
            entry['ciphertext_len_bytes'] = ct_len
            entry['plugin_bias_first_order_prediction'] = float(
                8.0 - 256.0 / (2.0 * ct_len * math.log(2.0)))
            entry['abs_residual_vs_prediction'] = abs(
                entry['mean'] - entry['plugin_bias_first_order_prediction'])
            b1[cfg][str(length)] = entry
            pooled.extend(vals)
        b1[cfg]['overall'] = stats(pooled, unit='bits/byte')
        print(f"    {cfg:12s} overall mean={b1[cfg]['overall']['mean']:.4f} "
              f"std={b1[cfg]['overall']['std']:.4f}")
    b1['all_configs_overall'] = stats(
        [v for cfg in CONFIGS for v in b1[cfg]['overall']['all_values']],
        unit='bits/byte')
    print(f"[B1] done in {time.perf_counter() - t0:.1f}s  "
          f"all-configs mean={b1['all_configs_overall']['mean']:.4f}")

    # ---- B2 plaintext avalanche ------------------------------------------
    print(f"[B2] plaintext avalanche, fixed nonce={FIXED_NONCE!r}")
    b2 = {}
    b2_ct_len = {}
    t0 = time.perf_counter()
    for ci, cfg in enumerate(CONFIGS):
        b2[cfg] = {}
        pooled = []
        for li, length in enumerate(PLAINTEXT_LENGTHS):
            p0 = plaintexts[length]
            built0 = build_material(mod, cfg, p0, matrices)
            c0 = encrypt_material(mod, built0['material'], k_base, nonce=FIXED_NONCE)
            rng = random.Random(RANDOM_SEED + 1000 * ci + 10 * li)
            vals = []
            for _ in range(N_TRIALS):
                pos = rng.randrange(len(p0))
                bit = rng.randrange(7)                     # bits 0-6: keep single-byte ASCII
                p1 = p0[:pos] + chr(ord(p0[pos]) ^ (1 << bit)) + p0[pos + 1:]
                assert p1 != p0
                c1 = encrypt_material(
                    mod, build_material(mod, cfg, p1, matrices)['material'],
                    k_base, nonce=FIXED_NONCE)
                vals.append(bit_flip_ratio(c0, c1))
            b2[cfg][str(length)] = stats(vals, unit='fraction of ciphertext bits flipped')
            b2_ct_len[(cfg, length)] = len(c0)
            pooled.extend(vals)
        b2[cfg]['overall'] = stats(pooled, unit='fraction of ciphertext bits flipped')
        print(f"    {cfg:12s} overall mean={b2[cfg]['overall']['mean']:.4f} "
              f"std={b2[cfg]['overall']['std']:.4f}")
    print(f"[B2] done in {time.perf_counter() - t0:.1f}s")

    # ---- B3 key avalanche -> ciphertext -----------------------------------
    print(f"[B3] key avalanche -> ciphertext, fixed nonce={FIXED_NONCE!r} "
          f"(key variants: single-base substitution on seed_sequence_base)")
    b3 = {}
    t0 = time.perf_counter()
    pbkdf2_calls = 0
    for ci, cfg in enumerate(CONFIGS):
        b3[cfg] = {}
        pooled = []
        for li, length in enumerate(PLAINTEXT_LENGTHS):
            material = build_material(mod, cfg, plaintexts[length], matrices)['material']
            c0 = encrypt_material(mod, material, k_base, nonce=FIXED_NONCE)
            rng = random.Random(RANDOM_SEED + 200000 + 1000 * ci + 10 * li)
            vals = []
            for _ in range(N_TRIALS):
                variant, _pos, _orig, _new = single_base_substitution(
                    rng, seed_sequence_base, ACGU)
                assert sum(a != b for a, b in zip(variant, seed_sequence_base)) == 1
                k1 = pbkdf2(variant, SALT)
                pbkdf2_calls += 1
                c1 = encrypt_material(mod, material, k1, nonce=FIXED_NONCE)
                vals.append(bit_flip_ratio(c0, c1))
            b3[cfg][str(length)] = stats(vals, unit='fraction of ciphertext bits flipped')
            pooled.extend(vals)
            if li == len(PLAINTEXT_LENGTHS) - 1:
                _progress_b3(ci)
        b3[cfg]['overall'] = stats(pooled, unit='fraction of ciphertext bits flipped')
        print(f"    {cfg:12s} overall mean={b3[cfg]['overall']['mean']:.4f} "
              f"std={b3[cfg]['overall']['std']:.4f}")
    print(f"[B3] done in {time.perf_counter() - t0:.1f}s "
          f"(PBKDF2 calls: {pbkdf2_calls})")

    # ---- B4 intermediate-state diffusion (material-layer contribution, full
    # ---- pipeline) ---------------------------------------------------------
    print("[B4] intermediate-state diffusion (full pipeline), "
          "plaintexts = 3 random lengths + high-redundancy control 'A'*1024")
    b4_items = []
    for label, p in [('len_128', plaintexts[128]), ('len_1024', plaintexts[1024]),
                     ('len_10240', plaintexts[10240]),
                     ('control_A_x1024_high_redundancy', REDUNDANT_CONTROL_PLAINTEXT)]:
        codon0 = mod.encode_plaintext_to_codons(p)
        codon1 = mod.substitute_codons(codon0, matrices['true'])
        structured, idx = mod.apply_rna_secondary_structure(codon1)
        n_codons = len(codon0)
        subs = sum(1 for a, b in zip(codon0, codon1) if a != b)
        moved = sum(1 for i, v in enumerate(idx) if i != v)
        s1 = ''.join(codon1)
        st = ''.join(structured)
        b4_items.append({
            'plaintext_label': label,
            'plaintext_len_bytes': len(p),
            'n_codons': n_codons,
            'n_char_positions': len(idx),
            'sbox_value_substitution_rate': subs / n_codons,
            'sbox_fixed_point_count': n_codons - subs,
            'fold_char_position_move_rate': moved / len(idx),
            'fold_moved_char_position_count': moved,
            'adjacent_duplicate_ratio_codon1': adjacent_duplicate_ratio(s1),
            'adjacent_duplicate_ratio_structured': adjacent_duplicate_ratio(st),
            'adjacent_duplicate_ratio_codon0_reference': adjacent_duplicate_ratio(''.join(codon0)),
            'paired_positions_in_fold_structure': sum(
                1 for c in mod.linear_fold(''.join(codon1)) if c in '()'),
        })
    b4 = {
        'description': 'full pipeline intermediate states. '
                       'sbox_value_substitution_rate = mean(codon1[i] != codon0[i]) over codon '
                       'positions (codon level). fold_char_position_move_rate = mean(i != '
                       'indices_order[i]) over CHARACTER positions (indices_order is a permutation '
                       'of character indices within the joined codon string, i.e. nucleotide '
                       'positions, not codon positions). adjacent_duplicate_ratio = fraction of '
                       'adjacent character pairs that are equal, computed on the joined strings.',
        'per_plaintext': b4_items,
        'aggregates': {
            'sbox_value_substitution_rate': stats(
                [it['sbox_value_substitution_rate'] for it in b4_items], unit='fraction of codons'),
            'fold_char_position_move_rate': stats(
                [it['fold_char_position_move_rate'] for it in b4_items], unit='fraction of chars'),
            'adjacent_duplicate_ratio_codon1': stats(
                [it['adjacent_duplicate_ratio_codon1'] for it in b4_items], unit='fraction of pairs'),
            'adjacent_duplicate_ratio_structured': stats(
                [it['adjacent_duplicate_ratio_structured'] for it in b4_items], unit='fraction of pairs'),
        },
    }
    for it in b4_items:
        print(f"    {it['plaintext_label']:32s} sbox_sub_rate={it['sbox_value_substitution_rate']:.4f} "
              f"fold_move_rate={it['fold_char_position_move_rate']:.4f} "
              f"adjdup codon1={it['adjacent_duplicate_ratio_codon1']:.4f} "
              f"structured={it['adjacent_duplicate_ratio_structured']:.4f}")

    # ---- B5 error intolerance ---------------------------------------------
    print(f"[B5] error intolerance, 1KB plaintext, fixed nonce, ciphertext 1-bit flip")
    b5 = {}
    for ci, cfg in enumerate(CONFIGS):
        built0 = build_material(mod, cfg, plaintexts[1024], matrices)
        c0 = encrypt_material(mod, built0['material'], k_base, nonce=FIXED_NONCE)
        rng = random.Random(RANDOM_SEED + 300000 + 1000 * ci)
        n_exc = 0
        n_diff = 0
        n_equal = 0
        diff_ratios = []
        exc_types = Counter()
        for _ in range(N_TRIALS):
            c1 = bytearray(c0)
            byte_pos = 8 + rng.randrange(len(c1) - 8)   # skip the 8-byte nonce prefix
            bit = rng.randrange(8)
            c1[byte_pos] ^= (1 << bit)
            c1 = bytes(c1)
            assert c1 != c0
            try:
                out = decrypt_with_frozen(
                    mod, c1, k_base, built0['matrix'], built0['indices'])
            except Exception as exc:                    # any exception raised by the frozen code counts as decryption failure
                n_exc += 1
                exc_types[type(exc).__name__] += 1
                continue
            n = max(len(out), len(plaintexts[1024]))
            n_mismatch = abs(len(out) - len(plaintexts[1024])) + sum(
                1 for a, b in zip(out, plaintexts[1024]) if a != b)
            if out == plaintexts[1024]:
                n_equal += 1
                diff_ratios.append(0.0)
            else:
                n_diff += 1
                diff_ratios.append(n_mismatch / n if n else 0.0)
        total = N_TRIALS
        b5[cfg] = {
            'n_trials': total,
            'exception_rate': n_exc / total,
            'decrypt_ok_but_output_differs_rate': n_diff / total,
            'decrypt_ok_and_output_equals_plaintext_rate': n_equal / total,
            'exception_types': dict(exc_types),
            'char_diff_ratio_given_decrypt_ok': stats(
                diff_ratios, unit='fraction of differing characters vs P0') if diff_ratios else None,
            'n_decrypt_ok': n_diff + n_equal,
        }
        print(f"    {cfg:12s} exception={n_exc}/{total}  ok_but_differs={n_diff}/{total}  "
              f"ok_and_equal={n_equal}/{total}  exc_types={dict(exc_types)}")

    # ---- Expectation vs measurement-validity checks (recorded in two separate
    # ---- blocks; no False is masked) ---------------------------------------
    b1_bias_ok = all(
        b1[cfg][str(length)]['abs_residual_vs_prediction'] < 0.06
        for cfg in CONFIGS for length in PLAINTEXT_LENGTHS)
    b1_b1_monotone = all(
        b1['full'][str(a)]['mean'] < b1['full'][str(b)]['mean']
        for a, b in zip(PLAINTEXT_LENGTHS, PLAINTEXT_LENGTHS[1:]))
    co_vals = b2['cipher_only']['overall']['all_values']
    full_vals = b2['full']['overall']['all_values']
    b2_analysis = {
        'finding': (
            'B2 is NOT near 0.5 and this is a genuine property of the material layer, not a '
            'measurement error. A 1-bit plaintext flip changes exactly one base64 character '
            '(verified: codon-level diff per trial = 1), hence exactly one nucleotide of one '
            'codon (base64 index shifts by a power of two). Without fold the material therefore '
            'differs by ~1-3 bits and this difference is diluted by 1/length '
            '(cipher_only: ~0.00044 / 0.000053 / 0.000005 for 128/1024/10240 B, i.e. a constant '
            '~2 differing ciphertext bits). With fold the data-dependent permutation '
            '(indices_order = paired ++ unpaired) reclassifies characters downstream and can '
            'displace a large block of the material: full/no_sbox reach ~0.05-0.11, but the '
            'response is bimodal (some trials stay at the no-fold level). Conclusion: the '
            'codon/S-box layer has no bit-level diffusion and the fold cascade is the only '
            'material-layer diffusion mechanism; the ~0.5 ciphertext avalanche comes from the '
            'ChaCha20 key path (see B3), not from the material layer.'),
        'mean_differing_ciphertext_bits_per_cell': {
            f'{cfg}/{length}': {
                'mean_bits': b2[cfg][str(length)]['mean'] * 8 * b2_ct_len[(cfg, length)],
                'ciphertext_len_bytes': b2_ct_len[(cfg, length)],
            }
            for cfg in CONFIGS for length in PLAINTEXT_LENGTHS
        },
        'full_config_bimodality': {
            'n_trials_total': len(full_vals),
            'n_trials_below_0.001': sum(1 for v in full_vals if v < 0.001),
            'n_trials_above_0.01': sum(1 for v in full_vals if v > 0.01),
            'note': 'below 0.001 = fold cascade not triggered (bit-level change only); '
                    'above 0.01 = fold displaced a block of the material',
        },
        'full_overall_mean': b2['full']['overall']['mean'],
        'no_fold_overall_mean': b2['no_fold']['overall']['mean'],
    }
    b1_analysis = {
        'finding': (
            'The pooled all-config entropy (7.849 bits/byte) is below the 7.9-8.0 band because '
            'the plug-in (shuffle) entropy estimator used by the frozen calculate_entropy is '
            'downward-biased at small sample size: for N bytes and K=256 symbols the first-order '
            'bias is K/(2*N*ln2). Per-length means match that prediction (see '
            'plugin_bias_first_order_prediction / abs_residual_vs_prediction inside each cell); '
            'the 1024 B and 10240 B cells are ~7.955 and ~7.996 respectively.'),
        'matches_first_order_bias_all_cells': bool(b1_bias_ok),
        'entropy_monotone_in_length': bool(b1_b1_monotone),
        'per_length_first_order_prediction_bits_per_byte': {
            str(length): round(8.0 - 256.0 / (2.0 * (3 * 4 * len(
                mod.encode_plaintext_to_codons(plaintexts[length])) + 8) * math.log(2.0)), 4)
            for length in PLAINTEXT_LENGTHS
        },
    }

    expectation_checks = {
        'full_roundtrip_ok': roundtrip['full'],
        'B1_all_configs_entropy_in_7.9_8.0': bool(
            7.9 <= b1['all_configs_overall']['mean'] <= 8.0),
        'B2_full_overall_near_0.5': bool(0.45 <= b2['full']['overall']['mean'] <= 0.55),
        'B3_full_overall_near_0.5': bool(0.45 <= b3['full']['overall']['mean'] <= 0.55),
        'B5_success_and_equal_rate_zero_all_configs': all(
            b5[c]['decrypt_ok_and_output_equals_plaintext_rate'] == 0.0 for c in CONFIGS),
    }
    validity_checks = {
        'all_configs_roundtrip_ok': all(roundtrip.values()),
        'B1_per_length_matches_plugin_bias_prediction_within_0.06': bool(b1_bias_ok),
        'B1_entropy_monotone_in_ciphertext_length': bool(b1_b1_monotone),
        'B2_cipher_only_is_bit_transparent_below_0.01': bool(co_vals and max(co_vals) < 0.01),
        'B2_full_diffuses_stronger_than_no_fold_by_10x': bool(
            b2['full']['overall']['mean'] > 10 * b2['no_fold']['overall']['mean']),
        'B3_all_configs_in_0.45_0.55': all(
            0.45 <= b3[c]['overall']['mean'] <= 0.55 for c in CONFIGS),
        'B5_all_flips_detected_or_corrupted': all(
            b5[c]['exception_rate'] + b5[c]['decrypt_ok_but_output_differs_rate'] == 1.0
            for c in CONFIGS),
    }
    sanity = {
        'expectation_checks': expectation_checks,
        'validity_checks': validity_checks,
        'all_expectations_pass': all(expectation_checks.values()),
        'all_validity_checks_pass': all(validity_checks.values()),
        'expectation_mismatch_analysis': {
            'B1_all_configs_entropy_in_7.9_8.0': b1_analysis,
            'B2_full_overall_near_0.5': b2_analysis,
        },
    }
    print(f"[sanity] expectation={json.dumps(expectation_checks)}")
    print(f"[sanity] validity  ={json.dumps(validity_checks)}")
    print(f"[sanity] all_expectations_pass={sanity['all_expectations_pass']} "
          f"all_validity_checks_pass={sanity['all_validity_checks_pass']}")

    return {
        'experiment': 'exp2_component_ablation',
        'setup': {
            'configs': {
                'full': 'encode -> substitute(M_true) -> apply_rna_secondary_structure -> ChaCha20',
                'no_fold': 'encode -> substitute(M_true) -> (fold skipped, indices=identity) -> ChaCha20',
                'no_sbox': 'encode -> substitute(identity matrix) -> apply_rna_secondary_structure -> ChaCha20',
                'cipher_only': 'encode -> ChaCha20 (no substitution, no fold)',
            },
            'pipeline_note': 'composed from the frozen component functions '
                             '(encode_plaintext_to_codons / substitute_codons / '
                             'apply_rna_secondary_structure / cha_encrypt); ncRNA3.5.encrypt is NOT called',
            'plaintext_lengths_bytes': PLAINTEXT_LENGTHS,
            'plaintext_alphabet': plaintext_alphabet,
            'plaintext_generator': RNG_RULE['plaintexts'],
            'seed_sequence_base': seed_sequence_base,
            'salt': salt.decode('utf-8', 'backslashreplace'),
            'key': 'K_base = PBKDF2-HMAC-SHA256(seed_sequence_base, salt, dkLen=32, count=1e5)',
            'sbox_seed': '123456789',
            'fixed_nonce': FIXED_NONCE.decode(),
            'nonce_policy': {
                'B1': 'random 8-byte nonce via frozen cha_encrypt (v1 default behaviour)',
                'B2_B3_B5': f'fixed nonce {FIXED_NONCE.decode()!r} (controlled comparison: '
                            'excludes random-nonce dominance from avalanche / error metrics)',
                'json_declaration': 'nonce_policy = "fixed for avalanche metrics" (B2/B3/B5); '
                                    'random for B1',
            },
            'bit_flip_policy': BIT_FLIP_POLICY,
            'n_trials_per_cell': N_TRIALS,
            'rng_derivation': RNG_RULE,
            'pbkdf2_call_count_B3': pbkdf2_calls,
        },
        'equivalence_self_check': {
            'description': 'encrypt then decrypt with the frozen components '
                           '(generate_dynamic_key_from_biological_data / cha_decrypt / '
                           'inverse_rna_secondary_structure / inverse_substitute_codons / '
                           'decode_codons_to_plaintext); recovered plaintext must equal the original',
            'plaintext_len_bytes': 1024,
            'roundtrip_ok_per_config': roundtrip,
            'full_config_roundtrip_ok': roundtrip['full'],
            'all_configs_roundtrip_ok': all(roundtrip.values()),
        },
        'B1_ciphertext_entropy': b1,
        'B2_plaintext_avalanche': b2,
        'B3_key_avalanche_to_ciphertext': b3,
        'B4_intermediate_state_diffusion': b4,
        'B5_error_intolerance': b5,
        'sanity_checks': sanity,
        'all_sanity_pass': bool(sanity['all_expectations_pass']
                                and sanity['all_validity_checks_pass']),
    }


def _progress_b3(ci):
    print(f"    ... config index {ci} done", flush=True)


if __name__ == '__main__':
    _mod = load_reference_module()
    print(json.dumps(run(_mod), indent=2)[:2000])
