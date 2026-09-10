"""Run the TODO-8 attack-measurement suite (experiments 1-3) in order and
write results.json next to this file.

Run:  ~/miniconda3/envs/claude/bin/python run_all.py
"""
import json

from common import OUT_PATH, assert_environment, load_reference_module, meta_block

import exp1_verification_cost
import exp2_known_plaintext
import exp3_offline_search_rate


def main():
    versions = assert_environment()
    mod = load_reference_module()

    results = {"meta": meta_block(versions)}

    results["exp1"] = exp1_verification_cost.run(mod)
    results["exp2"] = exp2_known_plaintext.run(mod)
    results["exp3"] = exp3_offline_search_rate.run(mod)

    # Cross-check: exp3 end-to-end rate vs exp1 composed reject path.
    results["exp3"]["exp1_cross_check"] = {
        "expected_rate_from_exp1": results["exp1"]["rates_per_core_cands_per_s"][
            "implementation"
        ],
        "ratio_exp3_over_exp1": results["exp3"]["rate_cands_per_s_per_core"]
        / results["exp1"]["rates_per_core_cands_per_s"]["implementation"],
    }

    OUT_PATH.write_text(json.dumps(results, indent=2) + "\n")
    print(f"written: {OUT_PATH}")
    print(json.dumps({
        "exp2_all_pass": results["exp2"]["all_pass"],
        "exp3_true_seed_confirmed": results["exp3"]["true_seed_full_pipeline_confirms"],
        "guess_path_impl_ms": results["exp1"]["composed"]["guess_path_implementation"][
            "median_s"
        ]
        * 1e3,
        "rate_impl_cands_per_s": results["exp1"]["rates_per_core_cands_per_s"][
            "implementation"
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
