import argparse
import json
from datetime import datetime, timezone


def assemble(cpu_json, swiotlb_json, pcie_json, meta_extra=None):
    meta = {"security_bits": cpu_json.get("security_bits", 256),
            "aesni": cpu_json.get("aesni", False),
            "pclmulqdq": cpu_json.get("pclmulqdq", False),
            "measured_on": datetime.now(timezone.utc).isoformat()}
    if meta_extra:
        meta.update(meta_extra)
    return {
        "meta": meta,
        "cpu_crypto": {"aes_gcm": cpu_json["aes_gcm"], "gmac": cpu_json["gmac"]},
        "swiotlb": swiotlb_json,
        "pcie": pcie_json,
        "gpu_crypto": {"mode": "pcie_line_rate", "aes_gcm_gbps": None, "gmac_gbps": None},
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpu", required=True)
    ap.add_argument("--swiotlb", required=True)
    ap.add_argument("--pcie", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    with open(args.cpu) as f: cpu = json.load(f)
    with open(args.swiotlb) as f: sw = json.load(f)
    with open(args.pcie) as f: pcie = json.load(f)
    with open(args.out, "w") as f:
        json.dump(assemble(cpu, sw, pcie), f, indent=2)


if __name__ == "__main__":
    main()
