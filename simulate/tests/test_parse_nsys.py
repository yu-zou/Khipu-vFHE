import sqlite3
import pytest
from trace.parse_nsys import parse


def build_mock(path, multi_gpu=False):
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE StringIds (id INTEGER PRIMARY KEY, value TEXT);
      CREATE TABLE CUPTI_ACTIVITY_KIND_MEMCPY (
        start INTEGER, end INTEGER, bytes INTEGER, copyKind INTEGER,
        streamId INTEGER, deviceId INTEGER);
      CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL (
        start INTEGER, end INTEGER, streamId INTEGER, deviceId INTEGER, shortName INTEGER);
    """)
    con.execute("INSERT INTO StringIds VALUES (10, 'ckks_mul_kernel')")
    # H2D 1 MiB on stream 7 device 0
    con.execute("INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES (1000, 27000, 1048576, 1, 7, 0)")
    # tiny control copy 64 B
    con.execute("INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES (100, 200, 64, 1, 7, 0)")
    # kernel on stream 7
    dev2 = 1 if multi_gpu else 0
    con.execute("INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES (40000, 160400, 7, ?, 10)", (dev2,))
    # D2H 512 KiB
    con.execute("INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES (170000, 183000, 524288, 2, 7, 0)")
    con.commit(); con.close()


def test_parse_classifies_and_normalizes(tmp_path):
    db = tmp_path / "mock.sqlite"; build_mock(str(db))
    tr = parse(str(db), "ckks_mult_relin_rescale", "cold")
    assert tr["workload"] == "ckks_mult_relin_rescale"
    types = [e["type"] for e in tr["events"]]
    assert "DATA_H2D" in types and "CONTROL_H2D" in types and "DATA_D2H" in types and "KERNEL" in types
    # earliest event normalized to 0
    assert min(e["orig_start_us"] for e in tr["events"]) == 0.0
    kern = [e for e in tr["events"] if e["type"] == "KERNEL"][0]
    assert kern["kernel_name"] == "ckks_mul_kernel"
    assert kern["gpu_time_us"] == pytest.approx(120.4)


def test_single_gpu_guard(tmp_path):
    db = tmp_path / "multi.sqlite"; build_mock(str(db), multi_gpu=True)
    with pytest.raises(ValueError):
        parse(str(db), "w", "cold")
