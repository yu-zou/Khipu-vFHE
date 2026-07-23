from simulator.events import Event

SECMODES = ("aes-gcm", "gmac", "none")


def interp_gbps(curve, size_bytes):
    pts = sorted(curve, key=lambda p: p[0])
    if size_bytes <= pts[0][0]:
        return pts[0][1]
    if size_bytes >= pts[-1][0]:
        return pts[-1][1]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if x0 <= size_bytes <= x1:
            t = (size_bytes - x0) / (x1 - x0)
            return y0 + t * (y1 - y0)
    return pts[-1][1]


def _bytes_us(size_bytes, gbps):
    if gbps <= 0:
        return 0.0
    return size_bytes / (gbps * 1000.0)


class CostModel:
    def __init__(self, params: dict, secmode: str):
        if secmode not in SECMODES:
            raise ValueError(f"unknown secmode {secmode}")
        self.p = params
        self.secmode = secmode

    def cpu_crypto_us(self, size_bytes: int) -> float:
        if self.secmode == "none":
            return 0.0
        key = "gmac" if self.secmode == "gmac" else "aes_gcm"
        c = self.p["cpu_crypto"][key]
        return c["fixed_latency_us"] + _bytes_us(size_bytes, interp_gbps(c["throughput_curve"], size_bytes))

    def swiotlb_us(self, size_bytes: int, direction: str) -> float:
        if self.secmode == "none":
            return 0.0
        s = self.p["swiotlb"]
        gbps = s["private_to_shared_gbps"] if direction == "h2d" else s["shared_to_private_gbps"]
        return s["map_unmap_fixed_us"] + _bytes_us(size_bytes, gbps)

    def pcie_us(self, size_bytes: int, direction: str) -> float:
        pc = self.p["pcie"][direction]
        return pc["fixed_latency_us"] + _bytes_us(size_bytes, interp_gbps(pc["bandwidth_curve"], size_bytes))

    def gpu_crypto_us(self, size_bytes: int, direction: str) -> float:
        if self.secmode == "none":
            return 0.0
        g = self.p["gpu_crypto"]
        if g.get("mode") == "pcie_line_rate":
            explicit = g.get("gmac_gbps") if self.secmode == "gmac" else g.get("aes_gcm_gbps")
            if explicit:
                return _bytes_us(size_bytes, explicit)
            return self.pcie_us(size_bytes, direction)
        explicit = g.get("gmac_gbps") if self.secmode == "gmac" else g.get("aes_gcm_gbps")
        return _bytes_us(size_bytes, explicit or 0.0)

    def gpu_compute_us(self, event: Event) -> float:
        return event.gpu_time_us
