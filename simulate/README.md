# Prototype D — AES-GCM vs GMAC Confidential I/O Simulation

Trace-driven discrete-event simulation comparing AES-GCM and GMAC CPU<->GPU
confidential I/O overhead for FHE microbenchmarks.

Design spec: `docs/superpowers/specs/2026-07-23-prototype-d-gmac-simulation-design.md`.

Stages:
1. `measure/` — measure CPU crypto, SWIOTLB copy, PCIe bandwidth -> `data/params/system_params.json`
2. `trace/` — run FIDESlib microbenchmarks under nsys on one H100 -> `data/traces/*.json`
3. `simulator/` — replay traces under AES-GCM and GMAC -> `results/*.json`
4. `analyze/` — aggregate + plot

Run everything: `./run_all.sh`. Run simulator/analysis tests: `python -m pytest tests/ -v`.

Do NOT use the unrelated `simulation/` folder.
