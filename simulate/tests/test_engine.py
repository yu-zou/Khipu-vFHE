import json
from simulator.events import Trace, Event, EventType
from simulator.cost_model import CostModel
from simulator.engine import simulate_trace
from simulator.resources import CPU_CRYPTO


def cost(secmode="aes-gcm", caps=None):
    with open("tests/fixtures/tiny_params.json") as f:
        return CostModel(json.load(f), secmode)


def single_stream_trace():
    evs = [
        Event(0, EventType.DATA_H2D, 1, 65536, 0.0, 0.0),
        Event(1, EventType.KERNEL, 1, 0, 5.0, 10.0, kernel_name="k", gpu_time_us=10.0),
        Event(2, EventType.DATA_D2H, 1, 32768, 20.0, 0.0),
    ]
    return Trace("ckks_add", "warm", {}, evs)


def test_gmac_no_slower_than_aes_gcm():
    tr = single_stream_trace()
    with open("tests/fixtures/tiny_params.json") as f:
        p = json.load(f)
    aes = simulate_trace(tr, CostModel(p, "aes-gcm"))
    gmac = simulate_trace(tr, CostModel(p, "gmac"))
    assert gmac.end_to_end_us <= aes.end_to_end_us


def test_single_stream_serializes():
    # two H2D on same stream: total >= sum of their cpu_crypto (serialized)
    with open("tests/fixtures/tiny_params.json") as f:
        p = json.load(f)
    evs = [
        Event(0, EventType.DATA_H2D, 1, 1 << 20, 0.0, 0.0),
        Event(1, EventType.DATA_H2D, 1, 1 << 20, 1.0, 0.0),
    ]
    res = simulate_trace(Trace("w", "warm", {}, evs), CostModel(p, "aes-gcm"))
    assert res.end_to_end_us > 0
    # verify serialization — end-to-end must be at least sum of CPU crypto
    min_serial = sum(CostModel(p, "aes-gcm").cpu_crypto_us(1 << 20) for _ in evs)
    assert res.end_to_end_us >= min_serial, f"serialized stream too fast: {res.end_to_end_us} < {min_serial}"


def test_two_streams_overlap_beats_serial():
    with open("tests/fixtures/tiny_params.json") as f:
        p = json.load(f)
    same = [
        Event(0, EventType.DATA_H2D, 1, 1 << 20, 0.0, 0.0),
        Event(1, EventType.DATA_H2D, 1, 1 << 20, 0.0, 0.0),
    ]
    split = [
        Event(0, EventType.DATA_H2D, 1, 1 << 20, 0.0, 0.0),
        Event(1, EventType.DATA_H2D, 2, 1 << 20, 0.0, 0.0),
    ]
    r_same = simulate_trace(Trace("w", "warm", {}, same), CostModel(p, "aes-gcm"))
    r_split = simulate_trace(Trace("w", "warm", {}, split), CostModel(p, "aes-gcm"))
    # different streams overlap the non-shared stages -> not slower
    assert r_split.end_to_end_us <= r_same.end_to_end_us


def test_result_fields_present():
    res = simulate_trace(single_stream_trace(), cost())
    assert res.end_to_end_us > 0
    assert "gpu_compute" in res.stage_breakdown_us
    assert res.totals["n_kernels"] == 1
    assert 0.0 <= res.resource_utilization[CPU_CRYPTO] <= 1.0
    assert res.comms_us >= 0
    assert res.compute_us > 0
    assert res.comms_compute_ratio >= 0
    assert res.totals["h2d_bytes"] >= 0
    assert res.totals["d2h_bytes"] >= 0


def test_deterministic():
    tr = single_stream_trace()
    a = simulate_trace(tr, cost())
    b = simulate_trace(tr, cost())
    assert a.end_to_end_us == b.end_to_end_us
