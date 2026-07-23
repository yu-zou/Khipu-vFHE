import csv
from analyze.make_size_sweep import sweep


def test_sweep_produces_rows_and_speedup(tmp_path):
    out = tmp_path / "sweep.csv"
    rows = sweep("tests/fixtures/tiny_params.json", [4096, 1048576], str(out))
    assert len(rows) == 2
    for r in rows:
        assert r["gmac_us"] <= r["aes_gcm_us"]
        assert r["speedup"] >= 1.0
    read = list(csv.DictReader(open(out)))
    assert {int(r["size_bytes"]) for r in read} == {4096, 1048576}
