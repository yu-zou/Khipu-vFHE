import argparse
import csv
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def plot_end_to_end(summary_csv, out_path):
    rows = _read(summary_csv)
    workloads = sorted({r["workload"] for r in rows})
    modes = ["aes-gcm", "gmac"]
    fig, ax = plt.subplots()
    width = 0.35
    for i, mode in enumerate(modes):
        vals = []
        for wl in workloads:
            match = [float(r["end_to_end_us"]) for r in rows
                     if r["workload"] == wl and r["secmode"] == mode and r["keymode"] == "cold"]
            vals.append(match[0] if match else 0.0)
        ax.bar([x + i * width for x in range(len(workloads))], vals, width, label=mode)
    ax.set_xticks([x + width / 2 for x in range(len(workloads))])
    ax.set_xticklabels(workloads, rotation=30, ha="right")
    ax.set_ylabel("end-to-end (us)")
    ax.set_title("AES-GCM vs GMAC end-to-end (cold-key)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_cold_vs_warm(summary_csv, out_path):
    rows = _read(summary_csv)
    workloads = sorted({r["workload"] for r in rows})
    fig, ax = plt.subplots()
    width = 0.35
    for i, km in enumerate(["cold", "warm"]):
        vals = []
        for wl in workloads:
            match = [float(r["end_to_end_us"]) for r in rows
                     if r["workload"] == wl and r["secmode"] == "gmac" and r["keymode"] == km]
            vals.append(match[0] if match else 0.0)
        ax.bar([x + i * width for x in range(len(workloads))], vals, width, label=km)
    ax.set_xticks([x + width / 2 for x in range(len(workloads))])
    ax.set_xticklabels(workloads, rotation=30, ha="right")
    ax.set_ylabel("end-to-end (us)")
    ax.set_title("Cold-key vs warm-key (GMAC)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_stage_breakdown(summary_csv, out_path):
    rows = [r for r in _read(summary_csv) if r["secmode"] == "gmac" and r["keymode"] == "cold"]
    cats = ["cpu_crypto_us", "swiotlb_us", "pcie_h2d_us", "pcie_d2h_us", "gpu_crypto_us", "gpu_compute_us"]
    labels = [r["workload"] for r in rows]
    fig, ax = plt.subplots()
    bottom = [0.0] * len(rows)
    for cat in cats:
        vals = [float(r[cat]) for r in rows]
        ax.bar(labels, vals, bottom=bottom, label=cat.replace("_us", ""))
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_ylabel("time (us)")
    ax.set_title("Per-stage breakdown (GMAC, cold-key)")
    ax.legend(fontsize="small")
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_size_sweep(sweep_csv, out_path):
    rows = sorted(_read(sweep_csv), key=lambda r: int(r["size_bytes"]))
    sizes = [int(r["size_bytes"]) for r in rows]
    fig, ax = plt.subplots()
    ax.plot(sizes, [float(r["aes_gcm_us"]) for r in rows], marker="o", label="aes-gcm")
    ax.plot(sizes, [float(r["gmac_us"]) for r in rows], marker="s", label="gmac")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("transfer size (bytes)")
    ax.set_ylabel("time (us)")
    ax.set_title("AES-GCM vs GMAC across transfer size")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True)
    ap.add_argument("--sweep", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.outdir, exist_ok=True)
    plot_end_to_end(args.summary, os.path.join(args.outdir, "end_to_end.png"))
    plot_cold_vs_warm(args.summary, os.path.join(args.outdir, "cold_vs_warm.png"))
    plot_stage_breakdown(args.summary, os.path.join(args.outdir, "stage_breakdown.png"))
    plot_size_sweep(args.sweep, os.path.join(args.outdir, "size_sweep.png"))


if __name__ == "__main__":
    main()
