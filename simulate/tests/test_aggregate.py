import json
import csv
from analyze.aggregate import aggregate, write_summary_csv, write_speedup_csv


def _mk_result(tmp_path, workload, keymode, secmode, e2e):
    d = {
        "workload": workload, "keymode": keymode, "secmode": secmode,
        "end_to_end_us": e2e,
        "stage_breakdown_us": {"cpu_crypto": 10.0, "swiotlb": 5.0, "pcie_h2d": 3.0,
                                "pcie_d2h": 2.0, "gpu_crypto": 1.0, "gpu_compute": 100.0},
        "resource_busy_us": {"CPU_CRYPTO": 10.0, "PCIE_H2D": 3.0, "PCIE_D2H": 2.0},
        "resource_utilization": {"CPU_CRYPTO": 0.1, "PCIE_H2D": 0.02, "PCIE_D2H": 0.01},
        "comms_us": 21.0, "compute_us": 100.0, "comms_compute_ratio": 0.21,
        "totals": {"h2d_bytes": 100, "d2h_bytes": 50, "n_kernels": 1},
    }
    p = tmp_path / f"{workload}_{keymode}_{secmode}.json"
    p.write_text(json.dumps(d))
    return p


def test_aggregate_reads_rows(tmp_path):
    _mk_result(tmp_path, "ckks_add", "cold", "aes-gcm", 200.0)
    _mk_result(tmp_path, "ckks_add", "cold", "gmac", 150.0)
    rows = aggregate(str(tmp_path))
    assert len(rows) == 2
    assert {r["secmode"] for r in rows} == {"aes-gcm", "gmac"}
    add = [r for r in rows if r["secmode"] == "gmac"][0]
    assert add["gpu_compute_us"] == 100.0
    assert add["h2d_bytes"] == 100


def test_speedup_csv(tmp_path):
    _mk_result(tmp_path, "ckks_add", "cold", "aes-gcm", 200.0)
    _mk_result(tmp_path, "ckks_add", "cold", "gmac", 100.0)
    rows = aggregate(str(tmp_path))
    out = tmp_path / "speedup.csv"
    write_speedup_csv(rows, str(out))
    r = list(csv.DictReader(open(out)))[0]
    assert float(r["speedup"]) == 2.0


def test_summary_csv_written(tmp_path):
    _mk_result(tmp_path, "ckks_add", "cold", "aes-gcm", 200.0)
    rows = aggregate(str(tmp_path))
    out = tmp_path / "summary.csv"
    write_summary_csv(rows, str(out))
    read = list(csv.DictReader(open(out)))
    assert read[0]["workload"] == "ckks_add"
