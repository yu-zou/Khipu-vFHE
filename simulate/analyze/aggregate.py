import argparse
import csv
import glob
import json
import os

SUMMARY_FIELDS = [
    "workload", "keymode", "secmode", "end_to_end_us",
    "cpu_crypto_us", "swiotlb_us", "pcie_h2d_us", "pcie_d2h_us",
    "gpu_crypto_us", "gpu_compute_us",
    "comms_us", "compute_us", "comms_compute_ratio",
    "util_CPU_CRYPTO", "util_PCIE_H2D", "util_PCIE_D2H",
    "h2d_bytes", "d2h_bytes", "n_kernels",
]


def _row(d: dict) -> dict:
    sb = d["stage_breakdown_us"]
    util = d["resource_utilization"]
    tot = d["totals"]
    return {
        "workload": d["workload"], "keymode": d["keymode"], "secmode": d["secmode"],
        "end_to_end_us": d["end_to_end_us"],
        "cpu_crypto_us": sb.get("cpu_crypto", 0.0),
        "swiotlb_us": sb.get("swiotlb", 0.0),
        "pcie_h2d_us": sb.get("pcie_h2d", 0.0),
        "pcie_d2h_us": sb.get("pcie_d2h", 0.0),
        "gpu_crypto_us": sb.get("gpu_crypto", 0.0),
        "gpu_compute_us": sb.get("gpu_compute", 0.0),
        "comms_us": d["comms_us"], "compute_us": d["compute_us"],
        "comms_compute_ratio": d["comms_compute_ratio"],
        "util_CPU_CRYPTO": util.get("CPU_CRYPTO", 0.0),
        "util_PCIE_H2D": util.get("PCIE_H2D", 0.0),
        "util_PCIE_D2H": util.get("PCIE_D2H", 0.0),
        "h2d_bytes": tot.get("h2d_bytes", 0),
        "d2h_bytes": tot.get("d2h_bytes", 0),
        "n_kernels": tot.get("n_kernels", 0),
    }


def aggregate(results_dir: str):
    rows = []
    for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        with open(path) as f:
            d = json.load(f)
        if "stage_breakdown_us" not in d:
            continue
        rows.append(_row(d))
    return rows


def write_summary_csv(rows, out_path):
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_speedup_csv(rows, out_path):
    by_key = {}
    for r in rows:
        by_key.setdefault((r["workload"], r["keymode"]), {})[r["secmode"]] = r["end_to_end_us"]
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["workload", "keymode", "aes_gcm_us", "gmac_us", "speedup"])
        w.writeheader()
        for (wl, km), m in sorted(by_key.items()):
            aes = m.get("aes-gcm")
            gmac = m.get("gmac")
            if aes is None or gmac is None or gmac == 0:
                continue
            w.writerow({"workload": wl, "keymode": km, "aes_gcm_us": aes,
                        "gmac_us": gmac, "speedup": aes / gmac})


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    rows = aggregate(args.results_dir)
    write_summary_csv(rows, args.out)
    write_speedup_csv(rows, os.path.join(os.path.dirname(args.out) or ".", "speedup.csv"))


if __name__ == "__main__":
    main()
