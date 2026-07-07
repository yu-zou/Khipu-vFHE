#include "server/workload_registry.h"

namespace tee {

namespace {
WorkloadRegistry g_registry;
}

WorkloadRegistry& get_workload_registry() {
    return g_registry;
}

void register_noop(WorkloadRegistry& registry);
void register_toy(WorkloadRegistry& registry);
void register_small(WorkloadRegistry& registry);
void register_medium(WorkloadRegistry& registry);
void register_micro_add(WorkloadRegistry& registry);
void register_micro_mul(WorkloadRegistry& registry);
void register_micro_mul_rescale(WorkloadRegistry& registry);
void register_micro_rotate(WorkloadRegistry& registry);
void register_app_matvec(WorkloadRegistry& registry);
void register_app_inference(WorkloadRegistry& registry);

void register_all_workloads() {
    register_noop(g_registry);
    register_toy(g_registry);
    register_small(g_registry);
    register_medium(g_registry);
    register_micro_add(g_registry);
    register_micro_mul(g_registry);
    register_micro_mul_rescale(g_registry);
    register_micro_rotate(g_registry);
    register_app_matvec(g_registry);
    register_app_inference(g_registry);
}

}  // namespace tee
