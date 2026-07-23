import json
import pytest
from simulator.cost_model import CostModel, interp_gbps


def load_params():
    with open("tests/fixtures/tiny_params.json") as f:
        return json.load(f)


def test_interp_clamps_and_interpolates():
    curve = [[1000, 2.0], [2000, 4.0]]
    assert interp_gbps(curve, 500) == 2.0        # clamp low
    assert interp_gbps(curve, 3000) == 4.0       # clamp high
    assert interp_gbps(curve, 1500) == 3.0       # midpoint


def test_gmac_cheaper_than_aes_gcm():
    p = load_params()
    aes = CostModel(p, "aes-gcm")
    gmac = CostModel(p, "gmac")
    size = 1 << 20
    assert gmac.cpu_crypto_us(size) < aes.cpu_crypto_us(size)


def test_cpu_crypto_formula():
    p = load_params()
    aes = CostModel(p, "aes-gcm")
    # 1 MiB at 4.0 GB/s = 1048576/(4*1000) us + 1.0 fixed
    expected = 1048576 / (4.0 * 1000.0) + 1.0
    assert aes.cpu_crypto_us(1 << 20) == pytest.approx(expected)


def test_none_mode_zeroes_crypto_and_swiotlb():
    p = load_params()
    none = CostModel(p, "none")
    assert none.cpu_crypto_us(1 << 20) == 0.0
    assert none.swiotlb_us(1 << 20, "h2d") == 0.0
    assert none.gpu_crypto_us(1 << 20, "h2d") == 0.0
    assert none.pcie_us(1 << 20, "h2d") > 0.0


def test_gpu_crypto_pcie_line_rate_equals_pcie():
    p = load_params()
    aes = CostModel(p, "aes-gcm")
    size = 1 << 20
    assert aes.gpu_crypto_us(size, "h2d") == pytest.approx(aes.pcie_us(size, "h2d"))
