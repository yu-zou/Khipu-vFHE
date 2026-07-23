import argparse
import csv
import json
from simulator.events import Trace, Event, EventType
from simulator.cost_model import CostModel
from simulator.engine import simulate_trace


def _one(params, size, secmode):
    ev = Event(0, EventType.DATA_H2D, 1, size, 0.0, 0.0)
    tr = Trace("sizesweep", "warm", {}, [ev])
    return simulate_trace(tr, CostModel(params, secmode)).end_to_end_us


def sweep(params_path, sizes, out_csv):
    with open(params_path) as f:
        params = json.load(f)
    rows = []
    for size in sizes:
        aes = _one(params, size, "aes-gcm")
        gmac = _one(params, size, "gmac")
        rows.append({"size_bytes": size, "aes_gcm_us": aes, "gmac_us": gmac,
                     "speedup": aes / gmac if gmac > 0 else 0.0})
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["size_bytes", "aes_gcm_us", "gmac_us", "speedup"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sizes", default="4096,16384,65536,262144,1048576,4194304,16777216")
    args = ap.parse_args(argv)
    sizes = [int(x) for x in args.sizes.split(",")]
    sweep(args.params, sizes, args.out)


if __name__ == "__main__":
    main()
