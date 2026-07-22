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
| noop | 67046 | 0 | 622 | 28782 | 3241 |
| toy | 66258 | 2610 | 704 | 29468 | 3199 |
| small | 67799 | 3007 | 693 | 30682 | 3220 |
| medium | 66852 | 3630 | 943 | 29712 | 3150 |
| BGV-Add-4K | 66178 | 400 | 662 | 29225 | 3247 |
| BGV-Mul-4K | 67347 | 1149 | 697 | 29450 | 3183 |

**Prototype B (ZK):**

| Workload | input_loading | eval | witness | proof |
|----------|--------------:|-----:|--------:|------:|
| noop | 5655 | 0 | 0 | 0 |
| toy | 7024 | 2717 | 241385 | 9697075 |
| small | 8376 | 3022 | 656418 | 19616637 |
| medium | 10289 | 3560 | 1113460 | 25101371 |
| BGV-Add-4K | 6858 | 381 | 161669 | 0 |
| BGV-Mul-4K | 7038 | 3380 | 237906 | 9644663 |

### Client Verification Time (10 runs each, median, microseconds)

| Workload | Prototype E | Prototype B |
|----------|------------:|------------:|
| noop | 40956 | 0 |
| toy | 40130 | 1492166 |
| small | 41824 | 2958681 |
| medium | 42218 | 4449598 |
| BGV-Add-4K | 40923 | 0 |
| BGV-Mul-4K | 39897 | 1482548 |

Prototype B's client verification time is 0 for the noop and BGV-Add-4K
workloads because the empty R1CS system (no constraints) produces no proof,
so no client-side verification is needed. For BGV-Mul-4K, toy, small, and
medium the ZK proof is verified on the client side.

### Speedup

E server total = ctx + eval + outser + transcript + quote.
B server total = input_loading + eval + witness + proof.

| Workload | E server total | B server total | Ratio (B/E) |
|----------|---------------:|---------------:|------------:|
| noop | 99691 | 5655 | 0.057 |
| toy | 102239 | 9948201 | 97.3 |
| small | 105401 | 20284453 | 192.5 |
| medium | 104287 | 26228680 | 251.5 |
| BGV-Add-4K | 99712 | 168908 | 1.69 |
| BGV-Mul-4K | 101826 | 9892987 | 97.2 |

The key comparison is attestation vs. proof overhead: Prototype E's
transcript + quote generation versus Prototype B's witness + proof generation.
For add-only workloads (noop, BGV-Add-4K) that produce no R1CS constraints,
Prototype B's server total is 0.057× and 1.69× of Prototype E's respectively
— i.e., the ZK pipeline is competitive or significantly faster for trivial
circuits. For multiply-containing workloads, Prototype B's ZK proof
generation dominates (9.9M–25.1M µs for proof alone), whereas Prototype E's
attestation overhead is essentially constant (~32 ms for transcript + quote)
regardless of circuit complexity. The B/E ratio for toy (97.3×), small
(192.5×), medium (251.5×), and BGV-Mul-4K (97.2×) shows that ZK proof
generation is 2–3 orders of magnitude slower than TDX attestation when
multiplications are present.

## Raw Measurements (all runs)

All times in microseconds.

### Prototype E (tee-vfhe-bgvrns, CPU)

**noop:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 70775 | 0 | 632 | 29219 | 3442 | 47270 |
| 2 | 67006 | 0 | 731 | 27856 | 3152 | 42218 |
| 3 | 67458 | 0 | 598 | 29112 | 3249 | 40830 |
| 4 | 66841 | 0 | 659 | 29361 | 3220 | 39834 |
| 5 | 68570 | 0 | 620 | 28260 | 3422 | 41606 |
| 6 | 67086 | 0 | 612 | 29609 | 3179 | 41189 |
| 7 | 66148 | 0 | 624 | 28452 | 3127 | 38928 |
| 8 | 66327 | 0 | 632 | 28322 | 3370 | 38707 |
| 9 | 66817 | 0 | 615 | 27930 | 3397 | 41083 |
| 10 | 68690 | 0 | 616 | 30115 | 3233 | 39470 |

**toy:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 65856 | 4071 | 706 | 30053 | 3257 | 39244 |
| 2 | 65383 | 11657 | 676 | 28698 | 3096 | 42889 |
| 3 | 65977 | 8002 | 704 | 29063 | 3351 | 41458 |
| 4 | 66694 | 1126 | 719 | 29750 | 3212 | 39563 |
| 5 | 65543 | 1097 | 694 | 30297 | 3371 | 40145 |
| 6 | 66155 | 19623 | 730 | 29187 | 3186 | 40115 |
| 7 | 67422 | 5613 | 717 | 30155 | 3136 | 40014 |
| 8 | 67343 | 1112 | 685 | 28692 | 3184 | 40724 |
| 9 | 66362 | 1150 | 677 | 29052 | 3062 | 41001 |
| 10 | 67070 | 1140 | 705 | 29768 | 3344 | 39200 |

**small:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 66722 | 2178 | 665 | 30811 | 3147 | 42914 |
| 2 | 67786 | 2197 | 693 | 31302 | 3367 | 41622 |
| 3 | 67031 | 6619 | 694 | 29714 | 3247 | 41669 |
| 4 | 69283 | 11174 | 704 | 31199 | 3451 | 47116 |
| 5 | 68222 | 8735 | 718 | 30553 | 3390 | 42802 |
| 6 | 67436 | 2170 | 686 | 28986 | 3189 | 40858 |
| 7 | 68118 | 2227 | 681 | 31222 | 3159 | 41980 |
| 8 | 67829 | 6486 | 696 | 30214 | 3204 | 41508 |
| 9 | 66411 | 3788 | 692 | 32044 | 3237 | 40728 |
| 10 | 67812 | 2127 | 700 | 30174 | 3130 | 43962 |

**medium:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 68210 | 3593 | 928 | 29473 | 3170 | 42365 |
| 2 | 67098 | 3596 | 960 | 30127 | 3117 | 45439 |
| 3 | 68815 | 3627 | 943 | 30225 | 3385 | 43958 |
| 4 | 67712 | 19596 | 943 | 29859 | 3202 | 46226 |
| 5 | 68292 | 3599 | 946 | 29498 | 3138 | 44650 |
| 6 | 66478 | 3634 | 943 | 30759 | 3151 | 39352 |
| 7 | 66607 | 3627 | 925 | 29129 | 3235 | 39705 |
| 8 | 65601 | 11922 | 933 | 29612 | 3144 | 38788 |
| 9 | 66410 | 9522 | 933 | 29023 | 3149 | 42072 |
| 10 | 66021 | 3645 | 950 | 29812 | 3135 | 40008 |

**BGV-Add-4K:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 64914 | 380 | 598 | 28065 | 3916 | 41298 |
| 2 | 65920 | 415 | 652 | 28981 | 3346 | 40070 |
| 3 | 66062 | 9909 | 662 | 29989 | 3133 | 40191 |
| 4 | 67068 | 366 | 668 | 28887 | 3367 | 42024 |
| 5 | 66171 | 385 | 652 | 28752 | 3298 | 42074 |
| 6 | 66538 | 4430 | 712 | 29488 | 3159 | 40933 |
| 7 | 66091 | 366 | 732 | 29289 | 3318 | 39114 |
| 8 | 69978 | 3607 | 632 | 29302 | 3165 | 40078 |
| 9 | 66185 | 6270 | 669 | 29940 | 3196 | 41560 |
| 10 | 66266 | 364 | 663 | 29162 | 3179 | 40914 |

**BGV-Mul-4K:**

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 70583 | 38930 | 703 | 28934 | 3328 | 40792 |
| 2 | 67486 | 1157 | 671 | 30114 | 3206 | 44062 |
| 3 | 69299 | 3867 | 698 | 28876 | 3115 | 40831 |
| 4 | 68227 | 1117 | 696 | 29495 | 3129 | 40236 |
| 5 | 67129 | 1154 | 711 | 29328 | 3088 | 38408 |
| 6 | 65275 | 1079 | 636 | 29671 | 3396 | 39154 |
| 7 | 65667 | 1116 | 688 | 30323 | 3160 | 39226 |
| 8 | 67208 | 1103 | 703 | 29087 | 3329 | 40986 |
| 9 | 65829 | 4643 | 697 | 29405 | 1391 | 39488 |
| 10 | 68950 | 1145 | 697 | 29581 | 3333 | 39559 |

### Prototype B (zk-vfhe, CPU)

All 60 measurements (6 workloads × 10 runs) completed successfully after the
ZK proof endianness fix.

**noop:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 5628 | 0 | 0 | 0 | 0 |
| 2 | 5975 | 0 | 0 | 0 | 0 |
| 3 | 6197 | 0 | 0 | 0 | 0 |
| 4 | 6070 | 0 | 0 | 0 | 0 |
| 5 | 5511 | 0 | 0 | 0 | 0 |
| 6 | 5682 | 0 | 0 | 0 | 0 |
| 7 | 5443 | 0 | 0 | 0 | 0 |
| 8 | 6721 | 0 | 0 | 0 | 0 |
| 9 | 5435 | 0 | 0 | 0 | 0 |
| 10 | 5573 | 0 | 0 | 0 | 0 |

**toy:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 6406 | 1079 | 245957 | 9477094 | 1456803 |
| 2 | 6549 | 1967 | 235072 | 9690016 | 1500340 |
| 3 | 7418 | 7604 | 237333 | 9549468 | 1479269 |
| 4 | 7229 | 6363 | 244152 | 9836556 | 1455563 |
| 5 | 7029 | 3860 | 235719 | 9704135 | 1501398 |
| 6 | 8417 | 1133 | 242279 | 9890898 | 1523574 |
| 7 | 6264 | 1087 | 244992 | 9593433 | 1483992 |
| 8 | 6778 | 1126 | 240491 | 9762541 | 1539245 |
| 9 | 7019 | 11006 | 229201 | 9646364 | 1480513 |
| 10 | 8019 | 3468 | 255940 | 9873254 | 1513038 |

**small:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 8206 | 2089 | 716425 | 19512925 | 2923391 |
| 2 | 8227 | 7228 | 650576 | 19588523 | 2956263 |
| 3 | 8518 | 3848 | 656487 | 19686828 | 2887847 |
| 4 | 8826 | 2114 | 652742 | 19646665 | 2961100 |
| 5 | 8663 | 2183 | 655399 | 19550185 | 2915248 |
| 6 | 8675 | 7394 | 658658 | 19745749 | 3036027 |
| 7 | 8380 | 2178 | 645179 | 19397414 | 2889827 |
| 8 | 8373 | 7476 | 674816 | 19806064 | 3050205 |
| 9 | 8340 | 9127 | 732509 | 19576218 | 3022319 |
| 10 | 8371 | 2196 | 656350 | 19644751 | 2982874 |

**medium:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 10334 | 3357 | 1100750 | 25549903 | 4313159 |
| 2 | 10268 | 3548 | 1120126 | 24856254 | 4427129 |
| 3 | 10346 | 8709 | 1106508 | 25101136 | 4493134 |
| 4 | 10310 | 3578 | 1088661 | 24949245 | 4445972 |
| 5 | 10259 | 4065 | 1130458 | 25374525 | 4516026 |
| 6 | 12065 | 3497 | 1149909 | 25395873 | 4373453 |
| 7 | 9771 | 3572 | 1083365 | 24777948 | 4453224 |
| 8 | 9978 | 3485 | 1140791 | 25101606 | 4364409 |
| 9 | 10013 | 3537 | 1106794 | 24971058 | 4476966 |
| 10 | 11957 | 4807 | 1155764 | 25360505 | 4489646 |

**BGV-Add-4K:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 7065 | 379 | 168703 | 0 | 0 |
| 2 | 7112 | 381 | 164594 | 0 | 0 |
| 3 | 7146 | 6414 | 169053 | 0 | 0 |
| 4 | 6481 | 365 | 190432 | 0 | 0 |
| 5 | 6971 | 381 | 155668 | 0 | 0 |
| 6 | 6746 | 5376 | 159162 | 0 | 0 |
| 7 | 6299 | 380 | 152770 | 0 | 0 |
| 8 | 6260 | 9194 | 163156 | 0 | 0 |
| 9 | 6412 | 374 | 160183 | 0 | 0 |
| 10 | 7132 | 5695 | 156908 | 0 | 0 |

**BGV-Mul-4K:**

| Run | input_loading | eval | witness | proof | client_verify |
|-----|--------------:|-----:|--------:|------:|--------------:|
| 1 | 7038 | 6344 | 234269 | 9829559 | 1500623 |
| 2 | 7458 | 5544 | 243093 | 9619671 | 1477856 |
| 3 | 6769 | 1090 | 243488 | 9823145 | 1480998 |
| 4 | 7143 | 6570 | 234502 | 9584208 | 1492534 |
| 5 | 6855 | 27367 | 250056 | 9874108 | 1454335 |
| 6 | 7129 | 1177 | 237077 | 9629838 | 1483536 |
| 7 | 6959 | 7550 | 245966 | 9494270 | 1469133 |
| 8 | 7038 | 1144 | 231104 | 9697359 | 1504741 |
| 9 | 7025 | 1217 | 238735 | 9478581 | 1481560 |
| 10 | 7038 | 1131 | 234592 | 9659489 | 1486965 |
