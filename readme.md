# Crypto-ncRNA

Bio-inspired key derivation primitives that exploit the computational complexity of RNA secondary-structure folding, with a symmetric ChaCha20 payload layer. This work was accepted at the ICLR 2025 Workshop on AI for Nucleic Acids.

This repository hosts the algorithm implementation, the baseline benchmark scripts used in the paper, the QUBO encoding tools for the quantum-optimization case study, and the measurement suites that produced every experimental figure reported in the manuscript.

## Citation

If you use this project or refer to the related algorithm, please cite:

```bibtex
@inproceedings{
wangxu2025cryptoncrna,
title={Crypto-nc{RNA}: Non-coding {RNA} (nc{RNA}) Based Encryption Algorithm},
author={WangXu and YiquanWang and Tin-Yeh HUANG},
booktitle={ICLR 2025 Workshop on AI for Nucleic Acids},
year={2025},
url={https://openreview.net/forum?id=j6ODUDw4vN}
}
```

The workshop paper is available on OpenReview at https://openreview.net/forum?id=j6ODUDw4vN.

## Layout

- `ncrna/` — current algorithm implementation (`ncRNA3.5.py`)
- `benchmarks/` — baseline benchmark scripts (AES-256, RSA-2048) and test harnesses for timing, throughput, entropy, and correctness comparisons
- `quantum/` — QUBO encoding generators for the RNA folding case study
- `attack_measure/` — offline candidate-verification cost, known-plaintext reconstruction, and checksum/malleability analysis
- `timing_measure/` — key-establishment and per-message timing, throughput, ciphertext entropy, and the ML-KEM-768 post-quantum baseline
- `ablation_measure/` — seed-to-key avalanche and component ablation over four pipeline configurations

## Requirements

- Python 3.12+
- pycryptodome (PBKDF2, ChaCha20, AES, RSA)
- numpy and matplotlib for the plotting helpers

Each results file (`.json`) next to the scripts records the exact package versions, random seed, and machine used for that run.

## Usage

Each measurement suite is self-contained and writes its results as JSON:

```
cd timing_measure && python run_all.py
cd attack_measure && python run_all.py
cd ablation_measure && python run_all.py
```
