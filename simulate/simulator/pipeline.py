from dataclasses import dataclass
from simulator.events import Event
from simulator.cost_model import CostModel
from simulator.resources import (
    CPU_CRYPTO, SWIOTLB_COPY, PCIE_H2D, PCIE_D2H,
    GPU_CRYPTO_H2D, GPU_CRYPTO_D2H, GPU_COMPUTE,
)


@dataclass
class Stage:
    resource: str
    duration_us: float
    category: str


def expand(event: Event, cost: CostModel):
    if event.is_kernel():
        return [Stage(GPU_COMPUTE, cost.gpu_compute_us(event), "gpu_compute")]
    n = event.size_bytes
    if event.is_h2d():
        return [
            Stage(CPU_CRYPTO, cost.cpu_crypto_us(n), "cpu_crypto"),
            Stage(SWIOTLB_COPY, cost.swiotlb_us(n, "h2d"), "swiotlb"),
            Stage(PCIE_H2D, cost.pcie_us(n, "h2d"), "pcie_h2d"),
            Stage(GPU_CRYPTO_H2D, cost.gpu_crypto_us(n, "h2d"), "gpu_crypto"),
        ]
    if event.is_d2h():
        return [
            Stage(GPU_CRYPTO_D2H, cost.gpu_crypto_us(n, "d2h"), "gpu_crypto"),
            Stage(PCIE_D2H, cost.pcie_us(n, "d2h"), "pcie_d2h"),
            Stage(SWIOTLB_COPY, cost.swiotlb_us(n, "d2h"), "swiotlb"),
            Stage(CPU_CRYPTO, cost.cpu_crypto_us(n), "cpu_crypto"),
        ]
    raise ValueError(f"unknown event type {event.type}")
