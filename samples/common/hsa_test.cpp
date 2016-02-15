#include "hsa_test.h"

#include <iostream>

#define PRINT_ATTRIBUTE(attribute, value, metric) \
  std::cout << #attribute " = " << value << " " << metric << std::endl;

static size_t ToMB(size_t size) {
  return (size / (1024 * 1024));
}

HsaTest::HsaTest(const char* test_name) : test_name_(test_name) {
  std::cout << "Running " << test_name_ << std::endl;
  std::cout << "------------------------------------------------\n";
}

HsaTest::~HsaTest() {}

void HsaTest::Init() {
  hsa_status_t stat = hsa_init();
  if (stat != HSA_STATUS_SUCCESS) {
    std::cerr << "hsa_init fail with status " << stat << std::endl;
  }

  stat = hsa_iterate_agents(IterateAgents, (void*)this);
}

void HsaTest::Cleanup() { hsa_shut_down(); }

hsa_status_t HsaTest::IterateAgents(hsa_agent_t agent, void* data) {
  HsaTest* hsatest = (HsaTest*)data;

  AgentProps prop(agent);

  if (prop.device_type == HSA_DEVICE_TYPE_CPU) {
    hsatest->cpus_.push_back(agent);
  } else if (prop.device_type == HSA_DEVICE_TYPE_GPU) {
    hsatest->gpus_.push_back(agent);
  }

  hsa_amd_memory_pool_t pools[3] = {{0}, {0}, {0}};
  hsa_status_t stat =
      hsa_amd_agent_iterate_memory_pools(agent, IteratePools, pools);

  hsatest->global_fine_[agent.handle] = pools[0];
  hsatest->global_coarse_[agent.handle] = pools[1];
  hsatest->group_[agent.handle] = pools[2];

  return HSA_STATUS_SUCCESS;
}

hsa_status_t HsaTest::IteratePools(hsa_amd_memory_pool_t pool, void* data) {
  hsa_amd_memory_pool_t* pools = (hsa_amd_memory_pool_t*)data;

  PoolProps prop(pool);

  if (prop.segment == HSA_AMD_SEGMENT_GLOBAL) {
    if (prop.global_flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED) {
      pools[0].handle = pool.handle;
    } else {
      pools[1].handle = pool.handle;
    }
  } else if (prop.segment == HSA_AMD_SEGMENT_GROUP) {
    pools[2].handle = pool.handle;
  }

  return HSA_STATUS_SUCCESS;
}

HsaTest::AgentProps::AgentProps(hsa_agent_t agent) {
  if (agent.handle == 0) {
    return;
  }

  hsa_agent_get_info(agent, HSA_AGENT_INFO_NAME, (void*)name);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_VENDOR_NAME, (void*)vendor_name);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_FEATURE, (void*)&feature);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_MACHINE_MODEL,
                     (void*)&machine_model);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_PROFILE, (void*)&profile);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_DEFAULT_FLOAT_ROUNDING_MODE,
                     (void*)&default_float_rounding_mode);
  hsa_agent_get_info(agent,
                     HSA_AGENT_INFO_BASE_PROFILE_DEFAULT_FLOAT_ROUNDING_MODES,
                     (void*)&base_profile_float_rounding_mode);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_FAST_F16_OPERATION,
                     (void*)&fast_f16_operation);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_WAVEFRONT_SIZE,
                     (void*)&wavefront_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_WORKGROUP_MAX_DIM,
                     (void*)workgroup_max_dim);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_WORKGROUP_MAX_SIZE,
                     (void*)&workgroup_max_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_GRID_MAX_DIM, (void*)&grid_max_dim);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_GRID_MAX_SIZE,
                     (void*)&grid_max_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_FBARRIER_MAX_SIZE,
                     (void*)&fbarrier_max_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_QUEUES_MAX, (void*)&queue_max);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_QUEUE_MIN_SIZE,
                     (void*)&queue_min_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_QUEUE_MAX_SIZE,
                     (void*)&queue_max_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_QUEUE_TYPE, (void*)&queue_type);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_NODE, (void*)&node);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, (void*)&device_type);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_CACHE_SIZE, (void*)cache_size);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_ISA, (void*)&isa);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_EXTENSIONS, (void*)extensions);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_VERSION_MAJOR,
                     (void*)&version_major);
  hsa_agent_get_info(agent, HSA_AGENT_INFO_VERSION_MINOR,
                     (void*)&version_minor);
}

HsaTest::PoolProps::PoolProps(hsa_amd_memory_pool_t pool) {
  if (pool.handle == 0) {
    return;
  }

  hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                               (void*)&segment);
  hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS,
                               (void*)&global_flag);
  hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_SIZE,
                               (void*)&size);
  hsa_amd_memory_pool_get_info(pool,
                               HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALLOWED,
                               (void*)&alloc_allowed);
  hsa_amd_memory_pool_get_info(pool,
                               HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_GRANULE,
                               (void*)&alloc_granule);
  hsa_amd_memory_pool_get_info(pool,
                               HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALIGNMENT,
                               (void*)&alloc_alignment);
  hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_ACCESSIBLE_BY_ALL,
                               (void*)&all_accessible);
}

void HsaTest::PrintAgentInfo(AgentProps& prop) {
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_NAME, prop.name, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_VENDOR_NAME, prop.vendor_name, "");

  const char* feature_strings[] = {"NONE", "HSA_AGENT_FEATURE_DISPATCH",
                                   "HSA_AGENT_FEATURE_AGENT_DISPATCH"};
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_FEATURE, feature_strings[prop.feature], "");

  const char* model_strings[] = {"HSA_MACHINE_MODEL_SMALL",
                                 "HSA_MACHINE_MODEL_LARGE"};
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_MACHINE_MODEL,
                  model_strings[prop.machine_model], "");

  const char* profile_strings[] = {"HSA_PROFILE_BASE", "HSA_PROFILE_FULL"};
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_PROFILE, profile_strings[prop.profile], "");

  const char* default_float_rounding_strings[] = {
      "HSA_DEFAULT_FLOAT_ROUNDING_MODE_DEFAULT",
      "HSA_DEFAULT_FLOAT_ROUNDING_MODE_ZERO",
      "HSA_DEFAULT_FLOAT_ROUNDING_MODE_NEAR"};
  PRINT_ATTRIBUTE(
      HSA_AGENT_INFO_DEFAULT_FLOAT_ROUNDING_MODE,
      default_float_rounding_strings[prop.default_float_rounding_mode], "");
  PRINT_ATTRIBUTE(
      HSA_AGENT_INFO_BASE_PROFILE_DEFAULT_FLOAT_ROUNDING_MODES,
      default_float_rounding_strings[prop.base_profile_float_rounding_mode],
      "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_FAST_F16_OPERATION, prop.fast_f16_operation,
                  "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_WAVEFRONT_SIZE, prop.wavefront_size, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_WORKGROUP_MAX_DIM[0],
                  prop.workgroup_max_dim[0], "");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_WORKGROUP_MAX_DIM[1],
                  prop.workgroup_max_dim[1], "");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_WORKGROUP_MAX_DIM[2],
                  prop.workgroup_max_dim[2], "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_WORKGROUP_MAX_SIZE, prop.workgroup_max_size,
                  "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_GRID_MAX_DIM.x, prop.grid_max_dim.x, "");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_GRID_MAX_DIM.y, prop.grid_max_dim.y, "");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_GRID_MAX_DIM.z, prop.grid_max_dim.z, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_GRID_MAX_SIZE, prop.grid_max_size, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_FBARRIER_MAX_SIZE, prop.fbarrier_max_size, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_QUEUES_MAX, prop.queue_max, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_QUEUE_MIN_SIZE, prop.queue_min_size, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_QUEUE_MAX_SIZE, prop.queue_max_size, "");

  const char* queue_type_strings[] = {"HSA_QUEUE_TYPE_MULTI",
                                      "HSA_QUEUE_TYPE_SINGLE"};
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_QUEUE_TYPE,
                  queue_type_strings[prop.queue_type], "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_NODE, prop.node, "");

  const char* device_type_strings[] = {
      "HSA_DEVICE_TYPE_CPU", "HSA_DEVICE_TYPE_GPU", "HSA_DEVICE_TYPE_DSP"};
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_DEVICE, device_type_strings[prop.device_type],
                  "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_CACHE_SIZE[0], prop.cache_size[0], "bytes");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_CACHE_SIZE[1], prop.cache_size[1], "bytes");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_CACHE_SIZE[2], prop.cache_size[2], "bytes");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_CACHE_SIZE[3], prop.cache_size[3], "bytes");

  std::string extensions = "";
  extensions += (prop.extensions[HSA_EXTENSION_FINALIZER])
                    ? "HSA_EXTENSION_FINALIZER | "
                    : "";
  extensions +=
      (prop.extensions[HSA_EXTENSION_IMAGES]) ? "HSA_EXTENSION_IMAGES | " : "";
  extensions += (prop.extensions[HSA_EXTENSION_AMD_PROFILER])
                    ? "HSA_EXTENSION_AMD_PROFILER "
                    : "";
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_EXTENSIONS, extensions, "");

  PRINT_ATTRIBUTE(HSA_AGENT_INFO_VERSION_MAJOR, prop.version_major, "");
  PRINT_ATTRIBUTE(HSA_AGENT_INFO_VERSION_MINOR, prop.version_minor, "");
}

void HsaTest::PrintPoolInfo(PoolProps& prop) {
  const char* segment_strings[] = {
      "HSA_SEGMENT_GLOBAL", "HSA_AMD_SEGMENT_READONLY",
      "HSA_AMD_SEGMENT_PRIVATE", "HSA_AMD_SEGMENT_GROUP"};
  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                  segment_strings[prop.segment], "");

  std::string global_flag = "";
  global_flag +=
      (prop.global_flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_KERNARG_INIT)
          ? "HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_KERNARG_INIT | "
          : "";
  global_flag +=
      (prop.global_flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED)
          ? "HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED | "
          : "";
  global_flag +=
      (prop.global_flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_COARSE_GRAINED)
          ? "HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_COARSE_GRAINED "
          : "";
  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS, global_flag, "");

  static const size_t kMb = 1024 * 1024;
  if (prop.size >= kMb) {
    PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_SIZE, ToMB(prop.size), "MB");
  } else {
    PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_SIZE, prop.size, "bytes");
  }

  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALLOWED,
                  prop.alloc_allowed, "");
  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_GRANULE,
                  prop.alloc_granule, "bytes");
  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALIGNMENT,
                  prop.alloc_alignment, "bytes");
  PRINT_ATTRIBUTE(HSA_AMD_MEMORY_POOL_INFO_ACCESSIBLE_BY_ALL,
                  prop.all_accessible, "");
}
