from simulator.resources import Resource, ResourcePool, ALL_RESOURCES, CPU_CRYPTO


def test_capacity_one_serializes():
    r = Resource("x", capacity=1)
    s0 = r.acquire(now=0.0); r.release(s0 + 10.0)   # busy [0,10]
    s1 = r.acquire(now=2.0)                          # must wait until 10
    assert s1 == 10.0


def test_capacity_two_overlaps():
    r = Resource("x", capacity=2)
    s0 = r.acquire(now=0.0); r.release(s0 + 10.0)
    s1 = r.acquire(now=1.0); r.release(s1 + 10.0)    # second unit free
    assert s1 == 1.0
    s2 = r.acquire(now=2.0)                           # both busy; wait earliest (10)
    assert s2 == 10.0


def test_busy_time_accumulates():
    r = Resource("x", capacity=1)
    s = r.acquire(0.0); r.release(s + 5.0, start_us=s)
    assert r.busy_us == 5.0


def test_pool_has_all_resources():
    pool = ResourcePool()
    for name in ALL_RESOURCES:
        assert pool[name].name == name
    assert pool[CPU_CRYPTO].capacity == 1


def test_pool_custom_capacity():
    pool = ResourcePool(capacities={CPU_CRYPTO: 4})
    assert pool[CPU_CRYPTO].capacity == 4
