import argparse
import json
from simulator.events import load_trace
from simulator.cost_model import CostModel
from simulator.engine import simulate_trace


def run(params_path, trace_path, secmode, out_path=None):
    with open(params_path) as f:
        params = json.load(f)
    trace = load_trace(trace_path)
    cost = CostModel(params, secmode)
    res = simulate_trace(trace, cost)
    d = {
        "workload": trace.workload,
        "keymode": trace.keymode,
        "secmode": secmode,
        "end_to_end_us": res.end_to_end_us,
        "stage_breakdown_us": res.stage_breakdown_us,
        "resource_busy_us": res.resource_busy_us,
        "resource_utilization": res.resource_utilization,
        "comms_us": res.comms_us,
        "compute_us": res.compute_us,
        "comms_compute_ratio": res.comms_compute_ratio,
        "totals": res.totals,
    }
    if out_path:
        with open(out_path, "w") as f:
            json.dump(d, f, indent=2)
    return d


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--secmode", required=True, choices=["aes-gcm", "gmac", "none"])
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    d = run(args.params, args.trace, args.secmode, args.out)
    if not args.out:
        print(json.dumps(d, indent=2))


if __name__ == "__main__":
    main()
