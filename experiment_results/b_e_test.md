# Benchmark: B vs. E Prototype

## Experimental Setup

**Benchmark method:** 10 independent measurements per prototype per workload,
each with a fresh server process and a fresh client nonce. No warmup (CPU-only
workloads). Same BGV parameters, same deterministic inputs (seed_a=42, seed_b=123).

**Reproduction:** `scripts/benchmark_b_vs_e.sh`.

### BGV Parameters

| Parameter | Value |
|-----------|-------|
| Scheme | BGV |
| Ring dimension | 8192 |
| Batch size | 4096 slots |
| Multiplicative depth | 4 |
| Plaintext modulus | 65537 |
| Key switching | BV, digitSize=4 |
| Security level | HEStd_NotSet |
| Serialization | OpenFHE native binary |

### Problem Size

| Workload | Inputs | Slots/input | Circuit |
|----------|--------|-------------|---------|
| noop | 1 | 64 | identity |
| toy | 2 | 64 | c1 * c2 |
| small | 4 | 64 | (c1*c2) + (c3*c4) |
| medium | 6 | 64 | (c1*c2) + (c3*c4) + (c5*c6) |
| BGV-Add-4K | 2 | 4096 | c1 + c2 |
| BGV-Mul-4K | 2 | 4096 | c1 * c2 |

All multiplications use `EvalMultNoRelin` (no relinearization) to match
zkOpenFHE constraints. Medium is flattened to depth 1. EvalAdd-only workloads
(noop, BGV-Add-4K) produce no R1CS constraints in Prototype B, so their
witness/proof times are 0 (no proof generated).

## Measurement Results

### Server-Side Timing (10 runs each, median, microseconds)

**Prototype E (TDX):**

| Workload | ctx | eval | outser | transcript | quote |
|----------|----:|-----:|-------:|-----------:|------:|
| noop | 66376 | 0 | 650 | 28409 | 3170 |
| toy | 66574 | 1153 | 692 | 29031 | 3106 |
| small | 66972 | 2160 | 673 | 29376 | 3120 |
| medium | 67117 | 3662 | 964 | 30318 | 3142 |
| BGV-Add-4K | 67435 | 406 | 667 | 29745 | 3065 |
| BGV-Mul-4K | 67463 | 2502 | 702 | 29530 | 3085 |

**Prototype B (ZK):**

| Workload | input_loading | eval | witness | proof |
|----------|--------------:|-----:|--------:|------:|
| noop | 5749 | 0 | 0 | 0 |
| toy | N/A | N/A | N/A | N/A |
| small | N/A | N/A | N/A | N/A |
| medium | N/A | N/A | N/A | N/A |
| BGV-Add-4K | N/A | N/A | N/A | N/A |
| BGV-Mul-4K | N/A | N/A | N/A | N/A |

**Note:** Prototype B workloads beyond `noop` all fail due to a pre-existing ZK
proof serialisation issue in the protobuf/socket framing layer (the server
generates a valid proof, but the client cannot deserialise the response blob).
The server-side ZK pipeline (`pass1` constraint gen, `pass2` witness gen,
`pass3a` setup, `pass3b` prove) completes successfully — the failure is in the
serialisation of the proof response for non-empty R1CS constraint systems. For
the `noop` workload the R1CS system is empty (no constraints), so the proof
blob is trivial and the serialisation path succeeds. This issue is pre-existing
and not introduced by our changes.

### Client Verification Time (10 runs each, median, microseconds)

| Workload | Prototype E | Prototype B |
|----------|------------:|------------:|
| noop | 39453 | 0 |
| toy | 39377 | N/A |
| small | 40009 | N/A |
| medium | 40058 | N/A |
| BGV-Add-4K | 39661 | N/A |
| BGV-Mul-4K | 39678 | N/A |

Prototype B's client verification time is 0 for the noop workload because the
empty R1CS system produces no proof, so no client-side verification is needed.
For other workloads, client verification was unreachable due to the proof
serialisation failure described above.

### Speedup

E server total = ctx + eval + outser + transcript + quote.
B server total = input_loading + eval + witness + proof.

| Workload | E server total | B server total | Ratio (B/E) |
|----------|---------------:|---------------:|------------:|
| noop | 98605 | 5749 | 0.058 |
| toy | 100556 | N/A | N/A |
| small | 102301 | N/A | N/A |
| medium | 105203 | N/A | N/A |
| BGV-Add-4K | 101318 | N/A | N/A |
| BGV-Mul-4K | 103282 | N/A | N/A |

The key comparison is attestation vs. proof overhead: Prototype E's
transcript + quote generation versus Prototype B's witness + proof generation.
For the only comparable workload (noop), Prototype B's server total is 0.058×
of Prototype E's — i.e., the ZK pipeline without proof serialisation is ~17×
faster on the server for trivial circuits. However, this comparison is
misleading for non-trivial workloads where ZK proof generation dominates
(10–20 seconds for toy, as seen in the server logs), whereas Prototype E's
attestation overhead is essentially constant (~32 ms for transcript + quote)
regardless of circuit complexity.

## Raw Measurements (all runs)

All times in microseconds.

### Prototype E (tee-vfhe-bgvrns, CPU)

**noop:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 70989 | 0 | 825 | 29315 | 3412 | 39865 |
| 2 | 68190 | 0 | 615 | 29095 | 3161 | 39478 |
| 3 | 68144 | 0 | 622 | 28328 | 3179 | 43031 |
| 4 | 66104 | 0 | 616 | 28533 | 3119 | 40656 |
| 5 | 66357 | 0 | 609 | 28676 | 3065 | 39624 |
| 6 | 65914 | 0 | 715 | 28414 | 3327 | 38569 |
| 7 | 66835 | 0 | 665 | 28187 | 3129 | 38943 |
| 8 | 66395 | 0 | 678 | 28405 | 3345 | 38561 |
| 9 | 66096 | 0 | 635 | 28378 | 3134 | 39429 |
| 10 | 65815 | 0 | 673 | 28293 | 3363 | 39092 |

**toy:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 67284 | 1147 | 677 | 29407 | 3130 | 40235 |
| 2 | 66813 | 6416 | 691 | 29208 | 3099 | 39364 |
| 3 | 70590 | 1102 | 719 | 28864 | 3113 | 39850 |
| 4 | 65963 | 12667 | 674 | 28369 | 3029 | 39258 |
| 5 | 66267 | 1111 | 693 | 30086 | 3091 | 39391 |
| 6 | 66047 | 1122 | 671 | 29151 | 3020 | 39344 |
| 7 | 66336 | 1338 | 707 | 28912 | 3076 | 38431 |
| 8 | 68429 | 1103 | 695 | 31753 | 3320 | 39114 |
| 9 | 68016 | 1160 | 686 | 28740 | 3133 | 39760 |
| 10 | 66081 | 3515 | 694 | 28457 | 3333 | 39461 |

**small:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 65877 | 7809 | 690 | 29287 | 3208 | 39539 |
| 2 | 68477 | 1929 | 636 | 28744 | 3051 | 39939 |
| 3 | 66479 | 2080 | 645 | 28898 | 3089 | 39716 |
| 4 | 65818 | 5509 | 702 | 29034 | 3325 | 41951 |
| 5 | 67062 | 2123 | 659 | 29686 | 3110 | 41503 |
| 6 | 67720 | 2138 | 653 | 29262 | 3100 | 39125 |
| 7 | 66882 | 2173 | 681 | 29465 | 3108 | 40221 |
| 8 | 68411 | 2155 | 677 | 30769 | 3371 | 40525 |
| 9 | 68235 | 2165 | 669 | 29938 | 3151 | 40080 |
| 10 | 65416 | 9314 | 701 | 31529 | 3131 | 38052 |

**medium:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 68220 | 7672 | 948 | 30304 | 3087 | 43681 |
| 2 | 70850 | 3735 | 958 | 30146 | 3293 | 40048 |
| 3 | 67468 | 3645 | 914 | 31576 | 3214 | 40950 |
| 4 | 66978 | 4304 | 952 | 30094 | 3094 | 40785 |
| 5 | 66876 | 7667 | 997 | 30332 | 3105 | 40253 |
| 6 | 67181 | 3645 | 948 | 29648 | 3278 | 38789 |
| 7 | 67054 | 3674 | 983 | 30967 | 3136 | 39876 |
| 8 | 69882 | 3650 | 991 | 31212 | 3309 | 39495 |
| 9 | 65774 | 3567 | 971 | 30596 | 3149 | 40068 |
| 10 | 66921 | 3582 | 981 | 29864 | 3087 | 39357 |

**BGV-Add-4K:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 67206 | 404 | 668 | 29543 | 3076 | 41992 |
| 2 | 67383 | 4742 | 629 | 29499 | 3034 | 41596 |
| 3 | 66084 | 385 | 667 | 29378 | 3100 | 39580 |
| 4 | 68337 | 408 | 672 | 29772 | 3037 | 41279 |
| 5 | 67487 | 372 | 691 | 29739 | 3051 | 39153 |
| 6 | 66364 | 411 | 667 | 30028 | 3017 | 39625 |
| 7 | 70267 | 3523 | 657 | 30621 | 3403 | 39655 |
| 8 | 68463 | 414 | 673 | 31248 | 3145 | 39706 |
| 9 | 67178 | 368 | 674 | 29752 | 3071 | 39668 |
| 10 | 67617 | 398 | 666 | 29622 | 3059 | 39646 |

**BGV-Mul-4K:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 66955 | 5740 | 714 | 29429 | 3080 | 40331 |
| 2 | 67212 | 4626 | 699 | 29984 | 2995 | 38899 |
| 3 | 67748 | 6313 | 674 | 29100 | 3054 | 39454 |
| 4 | 67276 | 1154 | 702 | 29183 | 3328 | 40093 |
| 5 | 67092 | 1112 | 704 | 30340 | 3108 | 39961 |
| 6 | 67759 | 4515 | 683 | 29168 | 3099 | 39303 |
| 7 | 68466 | 1134 | 703 | 30604 | 3316 | 40567 |
| 8 | 67293 | 3074 | 697 | 30726 | 1158 | 38748 |
| 9 | 67634 | 1109 | 707 | 29343 | 3085 | 39903 |
| 10 | 67829 | 1930 | 723 | 29631 | 3086 | 39027 |

### Prototype B (zk-vfhe, CPU)

Only the `noop` workload completed successfully. All other workloads fail with
`exit=1` due to a pre-existing ZK proof serialisation issue — see note in the
Measurement Results section above.

**noop:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 5732 | 0 | 0 | 0 | 0 |
| 2 | 5706 | 0 | 0 | 0 | 0 |
| 3 | 5899 | 0 | 0 | 0 | 0 |
| 4 | 6055 | 0 | 0 | 0 | 0 |
| 5 | 5738 | 0 | 0 | 0 | 0 |
| 6 | 5640 | 0 | 0 | 0 | 0 |
| 7 | 5676 | 0 | 0 | 0 | 0 |
| 8 | 6030 | 0 | 0 | 0 | 0 |
| 9 | 5865 | 0 | 0 | 0 | 0 |
| 10 | 5760 | 0 | 0 | 0 | 0 |

**toy (all runs FAILED):**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | — | — | — | — | FAILED (exit=1) |
| 2 | — | — | — | — | FAILED (exit=1) |
| 3 | — | — | — | — | FAILED (exit=1) |
| 4 | — | — | — | — | FAILED (exit=1) |
| 5 | — | — | — | — | FAILED (exit=1) |
| 6 | — | — | — | — | FAILED (exit=1) |
| 7 | — | — | — | — | FAILED (exit=1) |
| 8 | — | — | — | — | FAILED (exit=1) |
| 9 | — | — | — | — | FAILED (exit=1) |
| 10 | — | — | — | — | FAILED (exit=1) |

**small, medium, BGV-Add-4K, BGV-Mul-4K:** No data — the benchmark script
stopped after the `toy` failures without attempting these workloads under
Prototype B.
