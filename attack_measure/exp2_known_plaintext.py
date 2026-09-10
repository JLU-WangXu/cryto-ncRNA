"""Experiment 2 - known-plaintext reconstruction of the cipher-input material
(TODO-8 item 2).

Given only (i) a known plaintext, (ii) the codon-substitution matrix and
(iii) the permutation indices -- both delivered alongside the ciphertext as
decryption metadata by the released protocol (v1) -- the attacker re-encodes,
substitutes, re-predicts the structure and re-derives the permutation, and
reconstructs the exact ChaCha20 input. Byte equality against the true cipher
input (recovered with the genuine key in the harness) is asserted.

Configurations: the released demonstration vectors plus three seeded-random
configurations (32/64/128-nt seeds) to show the property is structural, not
an artifact of the demo constants.

Run:  ~/miniconda3/envs/claude/bin/python exp2_known_plaintext.py
"""
import hashlib
import json
import random
import string

from Crypto.Cipher import ChaCha20

from common import (
    DEMO_PLAINTEXT,
    DEMO_SALT,
    DEMO_SEED,
    DEMO_SEED_SEQUENCE,
    RANDOM_SEED,
    load_reference_module,
)

_PRINTABLE = string.ascii_letters + string.digits + string.punctuation + " "


def random_config(rng, n_seed_nt, plaintext_len):
    """Seeded-random configuration (deterministic given rng state order)."""
    return {
        "seed_sequence": "".join(rng.choice("ACGU") for _ in range(n_seed_nt)),
        "seed": str(rng.getrandbits(64)),
        "salt": bytes(rng.getrandbits(8) for _ in range(8)),
        "plaintext": "".join(rng.choice(_PRINTABLE) for _ in range(plaintext_len)),
    }


def run(mod):
    rng = random.Random(RANDOM_SEED)
    configs = {
        "A_demo_released_vectors": {
            "seed_sequence": DEMO_SEED_SEQUENCE,
            "seed": DEMO_SEED,
            "salt": DEMO_SALT,
            "plaintext": DEMO_PLAINTEXT,
        },
        "B32_random": random_config(rng, 32, 64),
        "B64_random": random_config(rng, 64, 96),
        "B128_random": random_config(rng, 128, 128),
    }

    results = []
    all_pass = True
    for name, cfg in configs.items():
        seed_sequence, seed = cfg["seed_sequence"], cfg["seed"]
        salt, plaintext = cfg["salt"], cfg["plaintext"]

        encrypted, sub_matrix, indices_order = mod.encrypt(
            plaintext, seed, seed_sequence, salt
        )
        payload = encrypted[:-32]
        nonce, ct = payload[:8], payload[8:]

        # --- attacker path: known plaintext + delivered metadata only ------
        codon_seq = mod.encode_plaintext_to_codons(plaintext)
        substituted = mod.substitute_codons(codon_seq, sub_matrix)
        material_recon_list, indices_recomputed = mod.apply_rna_secondary_structure(
            substituted
        )
        material_recon = "".join(material_recon_list).encode("utf-8")

        # --- ground truth: genuine key path (harness only) -----------------
        key = mod.generate_dynamic_key_from_biological_data(seed_sequence, salt)
        material_true = ChaCha20.new(key=key, nonce=nonce).decrypt(ct)

        byte_equal = material_true == material_recon
        indices_match = list(indices_recomputed) == list(indices_order)
        checksum_ok = hashlib.sha256(payload).digest() == encrypted[-32:]
        roundtrip_ok = (
            mod.decrypt(encrypted, seed, seed_sequence, salt, sub_matrix, indices_order)
            == plaintext
        )
        ok = byte_equal and indices_match and checksum_ok and roundtrip_ok
        all_pass &= ok

        results.append(
            {
                "config": name,
                "seed_length_nt": len(seed_sequence),
                "cipher_input_bytes": len(material_true),
                "cipher_input_sha256": hashlib.sha256(material_true).hexdigest(),
                "n_codon_symbols": len(material_true) // 3,
                "validity_false_positive_prob": (1.0 / 64.0) ** (len(material_true) // 3),
                "byte_equal": byte_equal,
                "indices_recomputed_match_delivered": indices_match,
                "checksum_sanity_ok": checksum_ok,
                "plaintext_roundtrip_ok": roundtrip_ok,
                "attacker_inputs": [
                    "known plaintext",
                    "delivered codon-substitution matrix",
                    "delivered permutation indices",
                    "public encoding/folding/permutation functions",
                ],
                "secret_inputs_used_by_attacker": [],
            }
        )

    return {"configs": results, "all_pass": all_pass}


if __name__ == "__main__":
    mod = load_reference_module()
    print(json.dumps(run(mod), indent=2))
