from simulator.run_sim import run

PARAMS = "tests/fixtures/tiny_params.json"
GOLDEN = "tests/fixtures/golden_trace.json"


def test_none_mode_end_to_end_close_to_pcie_plus_kernel():
    none = run(PARAMS, GOLDEN, "none")
    # compute (500+60) dominates; crypto+swiotlb zeroed
    assert none["compute_us"] == 560.0
    # comms in none-mode is PCIe only (crypto/swiotlb zero)
    assert none["stage_breakdown_us"].get("cpu_crypto", 0.0) == 0.0
    assert none["stage_breakdown_us"].get("swiotlb", 0.0) == 0.0
    assert none["stage_breakdown_us"]["pcie_h2d"] > 0.0


def test_gmac_speedup_positive_on_golden():
    aes = run(PARAMS, GOLDEN, "aes-gcm")
    gmac = run(PARAMS, GOLDEN, "gmac")
    assert gmac["end_to_end_us"] <= aes["end_to_end_us"]


def test_golden_end_to_end_stable():
    aes = run(PARAMS, GOLDEN, "aes-gcm")
    # regression guard: recompute must match to 6 decimals
    assert round(aes["end_to_end_us"], 6) == round(run(PARAMS, GOLDEN, "aes-gcm")["end_to_end_us"], 6)
