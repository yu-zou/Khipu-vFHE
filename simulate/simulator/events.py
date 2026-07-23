import json
from dataclasses import dataclass, field
from typing import Optional


class EventType:
    DATA_H2D = "DATA_H2D"
    DATA_D2H = "DATA_D2H"
    CONTROL_H2D = "CONTROL_H2D"
    CONTROL_D2H = "CONTROL_D2H"
    KERNEL = "KERNEL"


_H2D = {EventType.DATA_H2D, EventType.CONTROL_H2D}
_D2H = {EventType.DATA_D2H, EventType.CONTROL_D2H}


@dataclass
class Event:
    id: int
    type: str
    stream: int
    size_bytes: int
    orig_start_us: float
    orig_dur_us: float
    kernel_name: Optional[str] = None
    gpu_time_us: float = 0.0

    def is_h2d(self) -> bool:
        return self.type in _H2D

    def is_d2h(self) -> bool:
        return self.type in _D2H

    def is_kernel(self) -> bool:
        return self.type == EventType.KERNEL


@dataclass
class Trace:
    workload: str
    keymode: str
    source: dict
    events: list[Event] = field(default_factory=list)


def load_trace(path: str) -> Trace:
    with open(path) as f:
        raw = json.load(f)
    events = []
    for e in raw["events"]:
        events.append(Event(
            id=e["id"], type=e["type"], stream=e["stream"],
            size_bytes=e.get("size_bytes", 0),
            orig_start_us=e.get("orig_start_us", 0.0),
            orig_dur_us=e.get("orig_dur_us", 0.0),
            kernel_name=e.get("kernel_name"),
            gpu_time_us=e.get("gpu_time_us", 0.0),
        ))
    return Trace(workload=raw["workload"], keymode=raw["keymode"],
                 source=raw.get("source", {}), events=events)
