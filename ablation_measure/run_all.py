"""
TODO-10 ablation experiment entry point: runs exp1 (seed layer A1/A2/A3) and
exp2 (pipeline layer B1-B5) in order, writes the merged results.json, and
prints a summary.

Run: ~/miniconda3/envs/claude/bin/python run_all.py
"""
import json

from common import (
    OUT_PATH,
    RANDOM_SEED,
    assert_environment,
    function_fingerprints,
    load_reference_module,
    meta_block,
    set_threading_environment,
)

import exp1_seed_to_key_avalanche
import exp2_component_ablation


def main():
    set_threading_environment()
    versions = assert_environment()
    mod = load_reference_module()
    print(f"[ENV] frozen code sha256 = {meta_block(versions)['frozen_code_sha256']}")

    results = {
        'meta': meta_block(
            versions,
            extra={
                'component_function_sha256': function_fingerprints(mod),
                'nonce_policy': {
                    'B1_ciphertext_entropy': 'random 8-byte nonce (frozen cha_encrypt, v1 default)',
                    'B2_plaintext_avalanche': 'fixed for avalanche metrics (nonce=b"12345678")',
                    'B3_key_avalanche': 'fixed for avalanche metrics (nonce=b"12345678")',
                    'B5_error_intolerance': 'fixed for avalanche metrics (nonce=b"12345678")',
                },
                'trial_count_declaration': {
                    'exp1_A1': '2000 variants (single-base substitution of the 32-nt '
                               'seed_sequence_base), paired against the same K_base',
                    'exp1_A3': 'same 2000 variants as A1 (paired comparison)',
                    'exp1_A2': '2000 S-box seed variants (single-character substitution of '
                               '"123456789") + 30 sampled variants for the KDF-decoupling check',
                    'exp2_B1': '4 configs x 3 plaintext lengths (128/1024/10240 B) x 30 trials',
                    'exp2_B2': '4 configs x 3 lengths x 30 trials (1-bit plaintext flip each)',
                    'exp2_B3': '4 configs x 3 lengths x 30 trials (360 PBKDF2 key variants)',
                    'exp2_B4': '4 plaintexts (3 random lengths + high-redundancy control "A"*1024), '
                               'deterministic full-pipeline intermediate states, no trials',
                    'exp2_B5': '4 configs x 1 plaintext (1024 B) x 30 trials (1-bit ciphertext flip each)',
                },
                'kdf_declaration': 'PBKDF2-HMAC-SHA256, dkLen=32, count=100000 '
                                   '(identical to frozen generate_dynamic_key_from_biological_data)',
                'random_seed': RANDOM_SEED,
            },
        )
    }

    results['exp1_seed_to_key_avalanche'] = exp1_seed_to_key_avalanche.run(mod)
    results['exp2_component_ablation'] = exp2_component_ablation.run(mod)

    OUT_PATH.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwritten: {OUT_PATH}")

    # ---- Summary ---------------------------------------------------------
    e1 = results['exp1_seed_to_key_avalanche']
    e2 = results['exp2_component_ablation']

    def row(label, st):
        return (f"  {label:34s} mean={st['mean']:.4f} std={st['std']:.4f} "
                f"min={st['min']:.4f} max={st['max']:.4f} n={st['n']}")

    print("\n" + "=" * 72)
    print("TODO-10 ablation experiment summary")
    print("=" * 72)
    print(f"A1 KDF avalanche (32B key, 128 bit)  :")
    print(row('A1 PBKDF2 flip fraction', e1['A1_kdf_avalanche']['stat']))
    print(row('A3 sha256(1 round) flip fraction', e1['A3_sha256_single_round']['stat']))
    a2 = e1['A2_sbox_seed_ablation']
    print(row('A2 S-box seed diff fraction (/64)', a2['diff_fraction_vs_M_base']))
    print(row('A2 S-box matrix fixed points (/64)', a2['fixed_point_count']))
    print(f"  {'A2 decoupling identical_count':34s} = "
          f"{a2['decoupling_check']['identical_count']}/{a2['decoupling_check']['n_sampled']}")

    print("B1 ciphertext entropy (bits/byte, overall per config):")
    for cfg in exp2_component_ablation.CONFIGS:
        print(row(f'B1 {cfg}', e2['B1_ciphertext_entropy'][cfg]['overall']))
    print(row('B1 all configs', e2['B1_ciphertext_entropy']['all_configs_overall']))

    for tag, block in (('B2 plaintext avalanche', e2['B2_plaintext_avalanche']),
                       ('B3 key avalanche -> ciphertext', e2['B3_key_avalanche_to_ciphertext'])):
        print(f"{tag} (flip fraction, overall per config):")
        for cfg in exp2_component_ablation.CONFIGS:
            print(row(f'{tag.split()[0]} {cfg}', block[cfg]['overall']))

    print("B4 intermediate-state diffusion (full pipeline):")
    for it in e2['B4_intermediate_state_diffusion']['per_plaintext']:
        print(f"  {it['plaintext_label']:32s} sbox_sub_rate={it['sbox_value_substitution_rate']:.4f}"
              f"  sbox_fixed_points={it['sbox_fixed_point_count']}"
              f"  fold_move_rate={it['fold_char_position_move_rate']:.4f}"
              f"  adjdup codon1={it['adjacent_duplicate_ratio_codon1']:.4f}"
              f"  structured={it['adjacent_duplicate_ratio_structured']:.4f}")

    print("B5 error intolerance (1 bit ciphertext flip, 1KB):")
    for cfg in exp2_component_ablation.CONFIGS:
        b = e2['B5_error_intolerance'][cfg]
        print(f"  {cfg:12s} exception={b['exception_rate']:.3f}"
              f"  ok_but_differs={b['decrypt_ok_but_output_differs_rate']:.3f}"
              f"  ok_and_equal={b['decrypt_ok_and_output_equals_plaintext_rate']:.3f}"
              f"  exc_types={b['exception_types']}")

    print(f"equivalence self-check (full round-trip): "
          f"{e2['equivalence_self_check']['full_config_roundtrip_ok']}  "
          f"(all configs: {e2['equivalence_self_check']['all_configs_roundtrip_ok']})")
    print(f"sanity exp1 = {json.dumps(e1['sanity_checks'])}  all_pass={e1['all_sanity_pass']}")
    s2 = e2['sanity_checks']
    print(f"sanity exp2 expectation checks = {json.dumps(s2['expectation_checks'])}  "
          f"all_pass={s2['all_expectations_pass']}")
    print(f"sanity exp2 measurement validity = {json.dumps(s2['validity_checks'])}  "
          f"all_pass={s2['all_validity_checks_pass']}")
    if not s2['all_expectations_pass']:
        print("note: some exp2 expectation checks did not hold (see results.json -> "
              "sanity_checks.expectation_mismatch_analysis); these are gaps between the "
              "stated expectation and the measurement, recorded as-is")
    print("=" * 72)


if __name__ == '__main__':
    main()
