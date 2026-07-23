from simulator.events import load_trace, EventType


def test_load_trace_parses_events():
    tr = load_trace("tests/fixtures/tiny_trace.json")
    assert tr.workload == "ckks_add"
    assert tr.keymode == "warm"
    assert len(tr.events) == 3
    assert tr.events[0].type == EventType.DATA_H2D
    assert tr.events[0].size_bytes == 4096
    assert tr.events[1].is_kernel()
    assert tr.events[1].gpu_time_us == 10.0
    assert tr.events[2].is_d2h()


def test_non_kernel_gpu_time_defaults_zero():
    tr = load_trace("tests/fixtures/tiny_trace.json")
    assert tr.events[0].gpu_time_us == 0.0
