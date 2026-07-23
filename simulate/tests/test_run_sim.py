import json
from simulator.run_sim import run


def test_run_produces_result_dict(tmp_path):
    out = tmp_path / "res.json"
    d = run("tests/fixtures/tiny_params.json", "tests/fixtures/tiny_trace.json",
            "gmac", str(out))
    assert d["workload"] == "ckks_add"
    assert d["keymode"] == "warm"
    assert d["secmode"] == "gmac"
    assert d["end_to_end_us"] > 0
    written = json.load(open(out))
    assert written["secmode"] == "gmac"


def test_run_secmode_ordering(tmp_path):
    aes = run("tests/fixtures/tiny_params.json", "tests/fixtures/tiny_trace.json", "aes-gcm")
    gmac = run("tests/fixtures/tiny_params.json", "tests/fixtures/tiny_trace.json", "gmac")
    assert gmac["end_to_end_us"] <= aes["end_to_end_us"]
