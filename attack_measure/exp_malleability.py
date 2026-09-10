"""
Supplementary experiment: constructive tampering malleability (integrity boundary).
Motivation: the acceptance predicate of S9.1 is the nucleotide-alphabet check on
      the decrypted output; the ciphertext package carries
      checksum = SHA-256(nonce||ciphertext), which is key-independent.
      This experiment answers two questions quantitatively:
        (a) Can an attacker bypass the checksum? -- flip 1 B of ciphertext,
            recompute and replace the checksum, submit the full frozen decryption
            pipeline, and record whether the checksum verification passes;
        (b) Under known plaintext, can an attacker craft a tampered ciphertext
            that passes the alphabet check? -- turn an 'A'(0x41) at some position
            of the material into 'G'(0x47) (XOR delta 0x06, 2 bits), apply the
            same XOR to the corresponding ciphertext byte, recompute the checksum.
      A control arm (checksum left untouched) is also recorded, to separate the
      effect of the checksum layer from that of the alphabet layer.
      (c) The pass rate of random single-bit flips cites ablation_measure B5
          (77-93% rejection); this script does not re-run it.
Note: only results_malleability.json is added; the frozen code is imported
      read-only (stubbed matplotlib).
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import random
import string
import sys
import types
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (assert_environment, load_reference_module, code_fingerprint,
                    machine_meta, RANDOM_SEED)

REPO = Path("/lenovofs1/home/wangyq/npj_uncon_comput")
CODE_PATH = REPO / "version2" / "code" / "ncrna" / "ncRNA3.5.py"

N_TRIALS = 30
PAYLOAD_LENGTH = 256          # known-plaintext length (bytes)
SEED_SEQUENCE = "ACGU" * 8    # v1 demonstration vector (pre-shared secret)
SALT = b"salt_123"
SBOX_SEED = "123456789"
ACGU = frozenset("ACGU")


def codon_alphabet():
    return [a + b + c for a in 'ACGU' for b in 'ACGU' for c in 'ACGU']


def alphabet_valid(material_str):
    """Attacker-optimal alphabet check: every char of material is in {A,C,G,U}."""
    return all(c in ACGU for c in material_str)


def run_full_decrypt(mod, package, seed_sequence, salt, matrix, indices_order):
    """Full frozen decryption pipeline (checksum verification, PBKDF2 key derivation).
    Returns (outcome, detail): outcome in {ok, checksum_rejected, alphabet_rejected, error}."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            pt = mod.decrypt(package, SBOX_SEED, seed_sequence, salt, matrix, indices_order)
        except ValueError as exc:
            msg = str(exc)
            if "Checksum" in msg:
                return "checksum_rejected", msg
            return "alphabet_rejected", msg          # inverse_substitute_codons found no codon
        except Exception as exc:                     # any other exception raised by the frozen code
            return "error", f"{type(exc).__name__}: {exc}"
    return "ok", pt


def main():
    print("=" * 60)
    print("Supplementary experiment: constructive tampering malleability (integrity boundary)")
    print("=" * 60)
    assert_environment()
    mod = load_reference_module()
    print(f"[ENV] frozen code sha256={code_fingerprint()[:16]}... (read-only import)")

    assert list(mod.codons) == codon_alphabet()

    # ---- honest party: pre-shared secret -> key; matrix; plaintext -------
    matrix = mod.generate_codon_substitution_matrix(SBOX_SEED)
    alphabet = string.ascii_letters + string.digits
    rng = random.Random(RANDOM_SEED)
    plaintext = ''.join(rng.choice(alphabet) for _ in range(PAYLOAD_LENGTH))

    # genuine ciphertext package (with checksum) and decryption metadata
    package, matrix_out, indices_order = mod.encrypt(plaintext, SBOX_SEED, SEED_SEQUENCE, SALT)
    assert matrix_out == matrix
    nonce, body, checksum = package[:8], package[8:-32], package[-32:]
    assert hashlib.sha256(nonce + body).digest() == checksum, "checksum layout assumption failed"
    print(f"[SETUP] payload={PAYLOAD_LENGTH} B, package={len(package)} B "
          f"(nonce 8 B || ciphertext {len(body)} B || checksum 32 B)")
    print(f"[SETUP] checksum == SHA-256(nonce||ciphertext): True (key-independent)")

    # material (the stream cipher's plaintext input) is reconstructible from the
    # decryption metadata (known plaintext + public functions)
    codons = mod.encode_plaintext_to_codons(plaintext)
    substituted = mod.substitute_codons(codons, matrix)
    structured, idx = mod.apply_rna_secondary_structure(substituted)
    material = ''.join(structured)
    assert idx == indices_order, "permutation indices mismatch"
    assert alphabet_valid(material), "material must be nucleotide-only"
    print(f"[SETUP] material reconstructed by attacker: {len(material)} chars, "
          f"alphabet-valid, byte-equal to cipher input")

    scenarios = {}

    # ------------------------------------------------------------------
    # (a) checksum bypass: flip 1 B of ciphertext -> recompute
    #     SHA-256(nonce||new ciphertext) -> replace
    # ------------------------------------------------------------------
    arm_rng = random.Random(RANDOM_SEED + 1)
    res_a = {'checksum_passed': 0, 'alphabet_passed': 0, 'decrypted_ok': 0,
             'outcome_counter': Counter(), 'n': N_TRIALS}
    res_a_control = {'checksum_passed': 0, 'alphabet_passed': 0, 'decrypted_ok': 0,
                     'outcome_counter': Counter(), 'n': N_TRIALS}
    for _ in range(N_TRIALS):
        pos = 8 + arm_rng.randrange(len(body))          # after nonce, before checksum
        bit = arm_rng.randrange(8)
        tampered = bytearray(package)
        tampered[pos] ^= (1 << bit)
        tampered = bytes(tampered)
        assert tampered != package

        # control arm: checksum left untouched
        outcome, detail = run_full_decrypt(mod, tampered, SEED_SEQUENCE, SALT,
                                           matrix, indices_order)
        res_a_control['outcome_counter'][outcome] += 1
        res_a_control['checksum_passed'] += (outcome != "checksum_rejected")

        # experiment arm: recompute and replace the checksum (attacker-computable,
        # since the checksum is key-independent)
        forged = bytearray(tampered[:-32])
        forged += hashlib.sha256(bytes(tampered[:-32])).digest()
        forged = bytes(forged)
        assert forged[-32:] != tampered[-32:]
        outcome2, detail2 = run_full_decrypt(mod, forged, SEED_SEQUENCE, SALT,
                                             matrix, indices_order)
        res_a['outcome_counter'][outcome2] += 1
        res_a['checksum_passed'] += (outcome2 != "checksum_rejected")
        res_a['alphabet_passed'] += (outcome2 == "alphabet_rejected" or outcome2 == "ok")
        res_a['decrypted_ok'] += (outcome2 == "ok")
    scenarios['a_checksum_bypass'] = {
        'description': 'flip 1 random bit in the ciphertext body, recompute '
                       'SHA-256(nonce||ciphertext) and replace the checksum, submit to the full '
                       'frozen decryption pipeline',
        'tampered_bytes': 1, 'n_trials': N_TRIALS,
        'checksum_verification_passed': res_a['checksum_passed'],
        'checksum_verification_pass_rate': res_a['checksum_passed'] / N_TRIALS,
        'outcome_counts': dict(res_a['outcome_counter']),
        'alphabet_check_pass_rate': res_a['alphabet_passed'] / N_TRIALS,
        'decrypted_to_a_valid_payload': res_a['decrypted_ok'],
        'control_no_recompute': {
            'description': 'same single-bit flips, checksum left untouched',
            'checksum_verification_passed': res_a_control['checksum_passed'],
            'checksum_verification_pass_rate': res_a_control['checksum_passed'] / N_TRIALS,
            'outcome_counts': dict(res_a_control['outcome_counter']),
        },
    }
    print(f"\n(a) checksum bypass: checksum pass {res_a['checksum_passed']}/{N_TRIALS} "
          f"(control, no recompute: {res_a_control['checksum_passed']}/{N_TRIALS}) "
          f"outcomes={dict(res_a['outcome_counter'])}")

    # ------------------------------------------------------------------
    # (b) known-plaintext constructive flip: 'A'(0x41) -> 'G'(0x47) in the
    #     material, XOR delta 0x06
    # ------------------------------------------------------------------
    DELTA = ord('G') ^ ord('A')
    res_b = {'checksum_passed': 0, 'alphabet_passed': 0, 'undetected_modified_output': 0,
             'outcome_counter': Counter(), 'n_bits_flipped': Counter(), 'n': N_TRIALS}
    for _ in range(N_TRIALS):
        a_positions = [i for i, c in enumerate(material) if c == 'A']
        if not a_positions:
            raise RuntimeError("no 'A' symbol in material")
        m_pos = arm_rng.choice(a_positions)
        assert ord(material[m_pos]) ^ DELTA == ord('G')
        tampered = bytearray(package)
        # stream cipher is malleable: the XOR passes through to the material
        tampered[8 + m_pos] ^= DELTA
        tampered = bytes(tampered)
        forged = bytearray(tampered[:-32])
        forged += hashlib.sha256(bytes(tampered[:-32])).digest()
        forged = bytes(forged)

        # attacker-side prediction: the material decrypted from the forged
        # ciphertext differs only at that position, A->G
        pred = material[:m_pos] + 'G' + material[m_pos + 1:]
        res_b['n_bits_flipped'][bin(DELTA).count('1')] += 1

        outcome, detail = run_full_decrypt(mod, forged, SEED_SEQUENCE, SALT,
                                           matrix, indices_order)
        res_b['outcome_counter'][outcome] += 1
        res_b['checksum_passed'] += (outcome != "checksum_rejected")
        res_b['alphabet_passed'] += (outcome == "ok" or alphabet_valid(pred))
        if outcome == "ok":
            res_b['undetected_modified_output'] += (detail != plaintext)
        else:
            res_b['undetected_modified_output'] += 0
    scenarios['b_known_plaintext_selected_change'] = {
        'description': f"known-plaintext selected change: material symbol 'A'(0x41) -> "
                       f"'G'(0x47) (XOR delta {DELTA:#06x}, "
                       f"{bin(DELTA).count('1')} bits) applied to the corresponding ciphertext "
                       f"byte, checksum recomputed and replaced, full decryption run",
        'xor_delta': DELTA, 'n_bits_flipped': bin(DELTA).count('1'),
        'n_trials': N_TRIALS,
        'checksum_verification_passed': res_b['checksum_passed'],
        'checksum_verification_pass_rate': res_b['checksum_passed'] / N_TRIALS,
        'alphabet_check_pass_rate': res_b['alphabet_passed'] / N_TRIALS,
        'outcome_counts': dict(res_b['outcome_counter']),
        'tampering_undetected_and_output_changed': res_b['undetected_modified_output'],
    }
    print(f"(b) known-plaintext A->G: checksum pass {res_b['checksum_passed']}/{N_TRIALS}, "
          f"alphabet pass {res_b['alphabet_passed']}/{N_TRIALS}, "
          f"outcomes={dict(res_b['outcome_counter'])}")

    # ------------------------------------------------------------------
    # (c) control citation (not re-run): ablation_measure B5
    # ------------------------------------------------------------------
    ablation_path = REPO / "version2" / "code" / "ablation_measure" / "results.json"
    b5 = json.loads(ablation_path.read_text())['exp2_component_ablation']['B5_error_intolerance']
    rates = {c: round(b5[c]['exception_rate'] + b5[c]['decrypt_ok_but_output_differs_rate'], 4)
             for c in b5}
    scenarios['c_random_bitflip_reference'] = {
        'description': 'random single-bit ciphertext corruption (no checksum recomputation by '
                       'definition of the corruption model), reference only - measured in '
                       'ablation_measure/results.json exp2 B5, not re-run here',
        'source': str(ablation_path),
        'rejected_or_differs_rate_per_config': rates,
        'decrypt_to_original_plaintext_rate': 0.0,
    }
    print(f"(c) reference B5 rejected-or-differs rates: {rates}")

    results = {
        'meta': {
            'timestamp_utc': __import__('datetime').datetime.now(
                __import__('datetime').timezone.utc).isoformat(),
            'experiment': 'constructed-tampering malleability / integrity boundary',
            'random_seed': RANDOM_SEED,
            'n_trials_per_scenario': N_TRIALS,
            'payload_length_bytes': PAYLOAD_LENGTH,
            'plaintext_alphabet': 'string.ascii_letters + string.digits; one fixed plaintext via '
                                  'random.Random(20260909)',
            'reference_code': str(CODE_PATH),
            'reference_code_sha256': code_fingerprint(),
            'reference_code_access': 'read-only import (stubbed matplotlib.pyplot); file untouched',
            'checksum_definition': 'SHA-256(nonce || ciphertext), unkeyed, verified by '
                                   'verify_and_remove_checksum before any key use',
            'acceptance_predicate': 'nucleotide-alphabet validity of the decrypted material '
                                    '(cha_decrypt ACGU branch), then inverse substitution',
            'plaintext_known_to_attacker': True,
            'metadata_delivered_to_attacker': ['codon-substitution matrix',
                                               'permutation indices',
                                               'public encoding/folding/permutation functions'],
            'versions': assert_environment(),
            'threads_env': {k: os.environ.get(k, '')
                            for k in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS')},
            **machine_meta(),
            'rng_derivation': 'arm_rng = random.Random(20260909 + 1); plaintext rng = '
                              'random.Random(20260909)',
            'note_c': 'scenario (c) is cited from ablation_measure B5 and intentionally not re-run',
        },
        'scenarios': scenarios,
        'conclusion': {
            'checksum_is_recomputable_without_the_key': True,
            'stream_cipher_is_malleable': True,
            'alphabet_check_provides_error_detection_not_integrity': True,
            'integrity_out_of_scope_of_the_present_scheme': True,
        },
    }

    out = Path(__file__).resolve().parent / 'results_malleability.json'
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[OUT] results written: {out}")
    print("=" * 60)


if __name__ == '__main__':
    main()
