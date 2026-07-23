from dataclasses import dataclass, field
from simulator.events import Trace
from simulator.cost_model import CostModel
from simulator.pipeline import expand
from simulator.resources import ResourcePool, ALL_RESOURCES


@dataclass
class SimResult:
    end_to_end_us: float
    stage_breakdown_us: dict[str, float]
    resource_busy_us: dict[str, float]
    resource_utilization: dict[str, float]
    comms_us: float
    compute_us: float
    comms_compute_ratio: float
    totals: dict = field(default_factory=dict)


def simulate_trace(trace: Trace, cost: CostModel, capacities=None) -> SimResult:
    pool = ResourcePool(capacities=capacities)
    stream_ready = {}
    breakdown = {}
    end_to_end = 0.0
    h2d_bytes = d2h_bytes = 0
    n_kernels = 0

    ordered = sorted(trace.events, key=lambda e: (e.orig_start_us, e.id))
    for ev in ordered:
        if ev.is_kernel():
            n_kernels += 1
        elif ev.is_h2d():
            h2d_bytes += ev.size_bytes
        elif ev.is_d2h():
            d2h_bytes += ev.size_bytes

        stages = expand(ev, cost)
        t = stream_ready.get(ev.stream, 0.0)
        for st in stages:
            res = pool[st.resource]
            start = res.acquire(t)
            finish = start + st.duration_us
            res.release(finish, start_us=start)
            breakdown[st.category] = breakdown.get(st.category, 0.0) + st.duration_us
            t = finish
        stream_ready[ev.stream] = t
        end_to_end = max(end_to_end, t)

    busy = pool.busy_times()
    util = {n: (busy[n] / end_to_end if end_to_end > 0 else 0.0) for n in ALL_RESOURCES}
    compute_us = breakdown.get("gpu_compute", 0.0)
    comms_us = sum(v for k, v in breakdown.items() if k != "gpu_compute")
    ratio = comms_us / compute_us if compute_us > 0 else 0.0

    return SimResult(
        end_to_end_us=end_to_end,
        stage_breakdown_us=breakdown,
        resource_busy_us=busy,
        resource_utilization=util,
        comms_us=comms_us,
        compute_us=compute_us,
        comms_compute_ratio=ratio,
        totals={"h2d_bytes": h2d_bytes, "d2h_bytes": d2h_bytes, "n_kernels": n_kernels},
    )
