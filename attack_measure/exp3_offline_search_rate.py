"""Experiment 3 - offline candidate-seed verification rate (TODO-8 item 3).

The scheme's offline verifiability: a candidate seed is testable from the
ciphertext alone (no interaction with the encryptor). The acceptance
predicate of the released implementation (v1) is the nucleotide-alphabet
validity of the decrypted material (the appended SHA-256 checksum covers the
ciphertext and is key-independent). This experiment measures the end-to-end
reject path -- PBKDF2-HMAC-SHA256 (1e5 iterations) -> ChaCha20 decryption ->
early-exit alphabet check -- over 100 seeded-random wrong candidates, and
confirms the true seed via the full honest pipeline.

Run:  ~/miniconda3/envs/claude/bin/python exp3_offline_search_rate.py
"""
import json
import random
import time

from Crypto.Cipher import ChaCha20

from common import (
    DEMO_PLAINTEXT,
    DEMO_SALT,
    DEMO_SEED,
    DEMO_SEED_SEQUENCE,
    RANDOM_SEED,
    codon_alphabet_valid,
    load_reference_module,
)

M_WRONG = 100


def run(mod):
    encrypted, sub_matrix, indices_order = mod.encrypt(
        DEMO_PLAINTEXT, DEMO_SEED, DEMO_SEED_SEQUENCE, DEMO_SALT
    )
    payload = encrypted[:-32]
    nonce, ct = payload[:8], payload[8:]

    rng = random.Random(RANDOM_SEED + 1)
    wrong = set()
    while len(wrong) < M_WRONG:
        cand = "".join(rng.choice("ACGU") for _ in range(32))
        if cand != DEMO_SEED_SEQUENCE:
            wrong.add(cand)
    wrong = sorted(wrong)  # fixed order -> reproducible

    rejected = 0
    t0 = time.perf_counter()
    for cand in wrong:
        key = mod.generate_dynamic_key_from_biological_data(cand, DEMO_SALT)
        material = ChaCha20.new(key=key, nonce=nonce).decrypt(ct)
        if not codon_alphabet_valid(material):
            rejected += 1  # early exit: first non-ACGU byte rejects
    elapsed = time.perf_counter() - t0
    rate = len(wrong) / elapsed

    # True seed: passes the validity check and the full honest pipeline.
    key_true = mod.generate_dynamic_key_from_biological_data(
        DEMO_SEED_SEQUENCE, DEMO_SALT
    )
    material_true = ChaCha20.new(key=key_true, nonce=nonce).decrypt(ct)
    alphabet_pass = codon_alphabet_valid(material_true)
    plaintext_ok = (
        mod.decrypt(
            encrypted, DEMO_SEED, DEMO_SEED_SEQUENCE, DEMO_SALT, sub_matrix, indices_order
        )
        == DEMO_PLAINTEXT
    )

    return {
        "M_wrong_candidates": len(wrong),
        "rejected": rejected,
        "elapsed_s": elapsed,
        "rate_cands_per_s_per_core": rate,
        "true_seed_validity_pass": alphabet_pass,
        "true_seed_full_pipeline_confirms": plaintext_ok,
        "acceptance_predicate_note": (
            "the appended SHA-256 checksum covers nonce||ciphertext and is "
            "key-independent; the effective key-acceptance predicate is the "
            "nucleotide-alphabet validity of the decrypted material"
        ),
    }


if __name__ == "__main__":
    mod = load_reference_module()
    print(json.dumps(run(mod), indent=2))
