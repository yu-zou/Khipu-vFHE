import argparse
import json
import sqlite3


def parse(sqlite_path, workload, keymode, data_threshold=4096):
    con = sqlite3.connect(sqlite_path)
    con.row_factory = sqlite3.Row
    strings = {r["id"]: r["value"] for r in con.execute("SELECT id, value FROM StringIds")}

    devices = set()
    raw = []
    for r in con.execute("SELECT start,end,bytes,copyKind,streamId,deviceId FROM CUPTI_ACTIVITY_KIND_MEMCPY"):
        devices.add(r["deviceId"])
        is_h2d = r["copyKind"] == 1
        is_data = r["bytes"] >= data_threshold
        etype = ("DATA_H2D" if is_data else "CONTROL_H2D") if is_h2d else ("DATA_D2H" if is_data else "CONTROL_D2H")
        raw.append({"type": etype, "stream": r["streamId"], "size_bytes": r["bytes"],
                    "start_ns": r["start"], "end_ns": r["end"], "kernel_name": None})
    for r in con.execute("SELECT start,end,streamId,deviceId,shortName FROM CUPTI_ACTIVITY_KIND_KERNEL"):
        devices.add(r["deviceId"])
        raw.append({"type": "KERNEL", "stream": r["streamId"], "size_bytes": 0,
                    "start_ns": r["start"], "end_ns": r["end"],
                    "kernel_name": strings.get(r["shortName"], "unknown")})
    con.close()

    if len(devices) > 1:
        raise ValueError(f"multiple GPUs in trace: {sorted(devices)} (single-GPU only)")

    raw.sort(key=lambda e: e["start_ns"])
    t0 = raw[0]["start_ns"] if raw else 0
    events = []
    for i, e in enumerate(raw):
        dur_us = (e["end_ns"] - e["start_ns"]) / 1000.0
        ev = {"id": i, "type": e["type"], "stream": e["stream"], "size_bytes": e["size_bytes"],
              "orig_start_us": (e["start_ns"] - t0) / 1000.0, "orig_dur_us": dur_us,
              "kernel_name": e["kernel_name"]}
        if e["type"] == "KERNEL":
            ev["gpu_time_us"] = dur_us
        events.append(ev)

    return {"workload": workload, "keymode": keymode,
            "source": {"nsys_file": sqlite_path, "gpu": "H100 (non-CC)", "fideslib_commit": "b368ba6"},
            "events": events, "barriers": []}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--workload", required=True)
    ap.add_argument("--keymode", required=True, choices=["cold", "warm"])
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    tr = parse(args.sqlite, args.workload, args.keymode)
    with open(args.out, "w") as f:
        json.dump(tr, f, indent=2)


if __name__ == "__main__":
    main()
