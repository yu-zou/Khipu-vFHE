import heapq

CPU_CRYPTO = "CPU_CRYPTO"
SWIOTLB_COPY = "SWIOTLB_COPY"
PCIE_H2D = "PCIE_H2D"
PCIE_D2H = "PCIE_D2H"
GPU_CRYPTO_H2D = "GPU_CRYPTO_H2D"
GPU_CRYPTO_D2H = "GPU_CRYPTO_D2H"
GPU_COMPUTE = "GPU_COMPUTE"

ALL_RESOURCES = [
    CPU_CRYPTO, SWIOTLB_COPY, PCIE_H2D, PCIE_D2H,
    GPU_CRYPTO_H2D, GPU_CRYPTO_D2H, GPU_COMPUTE,
]


class Resource:
    def __init__(self, name: str, capacity: int = 1):
        self.name = name
        self.capacity = capacity
        self.busy_us = 0.0
        self._inflight = []  # min-heap of finish times

    def acquire(self, now: float) -> float:
        if len(self._inflight) < self.capacity:
            return now
        earliest = heapq.heappop(self._inflight)
        return max(now, earliest)

    def release(self, finish_us: float, start_us: float = None):
        heapq.heappush(self._inflight, finish_us)
        if start_us is not None:
            self.busy_us += max(0.0, finish_us - start_us)


class ResourcePool:
    def __init__(self, capacities=None):
        capacities = capacities or {}
        self._resources = {
            name: Resource(name, capacity=capacities.get(name, 1))
            for name in ALL_RESOURCES
        }

    def __getitem__(self, name: str) -> Resource:
        return self._resources[name]

    def busy_times(self) -> dict:
        return {name: r.busy_us for name, r in self._resources.items()}
