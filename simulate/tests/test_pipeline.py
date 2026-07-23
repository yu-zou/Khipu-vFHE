import json
from simulator.events import Event, EventType
from simulator.cost_model import CostModel
from simulator.pipeline import expand
from simulator.resources import (
    CPU_CRYPTO, SWIOTLB_COPY, PCIE_H2D, PCIE_D2H,
    GPU_CRYPTO_H2D, GPU_CRYPTO_D2H, GPU_COMPUTE,
)


def cost(secmode="aes-gcm"):
    with open("tests/fixtures/tiny_params.json") as f:
        return CostModel(json.load(f), secmode)


def test_h2d_chain_order():
    e = Event(0, EventType.DATA_H2D, 1, 65536, 0.0, 0.0)
    stages = expand(e, cost())
    assert [s.resource for s in stages] == [CPU_CRYPTO, SWIOTLB_COPY, PCIE_H2D, GPU_CRYPTO_H2D]
    assert all(s.duration_us > 0 for s in stages)


def test_d2h_chain_order():
    e = Event(1, EventType.DATA_D2H, 1, 65536, 0.0, 0.0)
    stages = expand(e, cost())
    assert [s.resource for s in stages] == [GPU_CRYPTO_D2H, PCIE_D2H, SWIOTLB_COPY, CPU_CRYPTO]


def test_kernel_single_stage_verbatim():
    e = Event(2, EventType.KERNEL, 1, 0, 0.0, 12.0, kernel_name="k", gpu_time_us=12.0)
    stages = expand(e, cost())
    assert len(stages) == 1
    assert stages[0].resource == GPU_COMPUTE
    assert stages[0].duration_us == 12.0


def test_none_mode_zero_crypto_stages_still_present():
    e = Event(0, EventType.DATA_H2D, 1, 65536, 0.0, 0.0)
    stages = expand(e, cost("none"))
    by_cat = {s.category: s.duration_us for s in stages}
    assert by_cat["cpu_crypto"] == 0.0
    assert by_cat["swiotlb"] == 0.0
    assert by_cat["pcie_h2d"] > 0.0
