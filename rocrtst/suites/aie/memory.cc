/*
 * =============================================================================
 *   ROC Runtime Conformance Release License
 * =============================================================================
 * The University of Illinois/NCSA
 * Open Source License (NCSA)
 *
 * Copyright (c) 2024, Advanced Micro Devices, Inc.
 * All rights reserved.
 *
 * Developed by:
 *
 *                 AMD Research and AMD ROC Software Development
 *
 *                 Advanced Micro Devices, Inc.
 *
 *                 www.amd.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal with the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimers.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimers in
 *    the documentation and/or other materials provided with the distribution.
 *  - Neither the names of <Name of Development Group, Name of Institution>,
 *    nor the names of its contributors may be used to endorse or promote
 *    products derived from this Software without specific prior written
 *    permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS WITH THE SOFTWARE.
 *
 */

#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "hsa/hsa.h"
#include "hsa/hsa_ext_amd.h"

namespace {

template <hsa_device_type_t DeviceType>
hsa_status_t discover_agents(hsa_agent_t agent, void *data) {
  if (data == nullptr) {
    return HSA_STATUS_ERROR_INVALID_ARGUMENT;
  }

  hsa_device_type_t device_type = {};
  const auto ret =
      hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
  if (ret != HSA_STATUS_SUCCESS) {
    return ret;
  }

  if (device_type == DeviceType) {
    auto *const agents = static_cast<std::vector<hsa_agent_t> *>(data);
    agents->push_back(agent);
  }

  return HSA_STATUS_SUCCESS;
}

hsa_status_t
discover_first_global_coarse_grain_mem_pool(hsa_amd_memory_pool_t pool,
                                            void *data) {
  if (!data) {
    return HSA_STATUS_ERROR_INVALID_ARGUMENT;
  }

  hsa_amd_memory_pool_global_flag_t flags = {};
  auto ret = hsa_amd_memory_pool_get_info(
      pool, HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS, &flags);
  if (ret != HSA_STATUS_SUCCESS) {
    return ret;
  }

  if ((flags & (HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED |
                HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_EXTENDED_SCOPE_FINE_GRAINED)) !=
      0x0) {
    auto *global_memory_pool = static_cast<hsa_amd_memory_pool_t *>(data);
    *global_memory_pool = pool;
    return HSA_STATUS_INFO_BREAK;
  }

  return HSA_STATUS_SUCCESS;
}

} // namespace

TEST_CASE("Export global coarse-grain memory") {
  REQUIRE(hsa_init() == HSA_STATUS_SUCCESS);

  std::vector<hsa_agent_t> gpu_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_GPU>,
                             &gpu_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!gpu_agents.empty());

  std::vector<hsa_agent_t> aie_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_AIE>,
                             &aie_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!aie_agents.empty());

  hsa_amd_memory_pool_t global_memory_pool = {};
  REQUIRE(hsa_amd_agent_iterate_memory_pools(
              gpu_agents.front(), discover_first_global_coarse_grain_mem_pool,
              &global_memory_pool) == HSA_STATUS_INFO_BREAK);
  REQUIRE(global_memory_pool.handle != 0);

  constexpr std::size_t buffer_size = 1024;
  constexpr std::size_t allocation_size = buffer_size * sizeof(std::uint32_t);
  std::uint32_t *buffer = {};
  const std::uint32_t flags = 0;
  REQUIRE(hsa_amd_memory_pool_allocate(
              global_memory_pool, allocation_size, flags,
              reinterpret_cast<void **>(&buffer)) == HSA_STATUS_SUCCESS);
  REQUIRE(buffer != nullptr);

  for (std::size_t i = 0; i < buffer_size; ++i) {
    buffer[i] = i;
  }

  SECTION("hsa_amd_portable_export_dmabuf") {
    int dma_buf_fd = -1;
    std::uint64_t dma_buf_offset = 0;
    REQUIRE(hsa_amd_portable_export_dmabuf(buffer, allocation_size, &dma_buf_fd,
                                           &dma_buf_offset) ==
            HSA_STATUS_SUCCESS);
    REQUIRE(dma_buf_fd > -1);

    const std::uint32_t num_agents = 1;
    auto *agent = &(aie_agents.front());
    const std::uint32_t flags = 0;
    std::size_t import_size = 0;
    std::uint32_t *import_buffer = nullptr;
    REQUIRE(hsa_amd_interop_map_buffer(
                num_agents, agent, dma_buf_fd, flags, &import_size,
                reinterpret_cast<void **>(&import_buffer), nullptr,
                nullptr) != HSA_STATUS_SUCCESS);

    REQUIRE(hsa_amd_portable_close_dmabuf(dma_buf_fd) == HSA_STATUS_SUCCESS);
  }

  SECTION("hsa_amd_agents_allow_access") {
    REQUIRE(hsa_amd_agents_allow_access(aie_agents.size(), aie_agents.data(),
                                        nullptr, buffer) != HSA_STATUS_SUCCESS);
  }

  REQUIRE(hsa_amd_memory_pool_free(buffer) == HSA_STATUS_SUCCESS);

  REQUIRE(hsa_shut_down() == HSA_STATUS_SUCCESS);
}

TEST_CASE("Export host memory") {
  REQUIRE(hsa_init() == HSA_STATUS_SUCCESS);

  std::vector<hsa_agent_t> aie_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_AIE>,
                             &aie_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!aie_agents.empty());

  std::vector<void *> agent_ptrs(aie_agents.size());

  constexpr std::size_t buffer_size = 1024;
  constexpr std::size_t allocation_size = buffer_size * sizeof(std::uint32_t);
  std::uint32_t *buffer = new std::uint32_t[buffer_size];
  REQUIRE(buffer != nullptr);

  for (std::size_t i = 0; i < buffer_size; ++i) {
    buffer[i] = i;
  }

  REQUIRE(hsa_amd_memory_lock(buffer, allocation_size, aie_agents.data(),
                              aie_agents.size(),
                              agent_ptrs.data()) != HSA_STATUS_SUCCESS);

  delete[] buffer;

  REQUIRE(hsa_shut_down() == HSA_STATUS_SUCCESS);
}

TEST_CASE("Vmem Set Access") {
  REQUIRE(hsa_init() == HSA_STATUS_SUCCESS);

  std::vector<hsa_agent_t> cpu_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_CPU>,
                             &cpu_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!cpu_agents.empty());

  std::vector<hsa_agent_t> gpu_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_GPU>,
                             &gpu_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!gpu_agents.empty());

  std::vector<hsa_agent_t> aie_agents;
  REQUIRE(hsa_iterate_agents(discover_agents<HSA_DEVICE_TYPE_AIE>,
                             &aie_agents) == HSA_STATUS_SUCCESS);
  REQUIRE(!aie_agents.empty());

  hsa_amd_memory_pool_t global_memory_pool = {};
  REQUIRE(hsa_amd_agent_iterate_memory_pools(
              gpu_agents.front(), discover_first_global_coarse_grain_mem_pool,
              &global_memory_pool) == HSA_STATUS_INFO_BREAK);
  REQUIRE(global_memory_pool.handle != 0);

  const std::uint64_t flags = 0;

  // allocate on GPU 0
  constexpr std::size_t buffer_size = 1024;
  constexpr std::size_t allocation_size = buffer_size * sizeof(std::uint32_t);
  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  REQUIRE(hsa_amd_vmem_handle_create(global_memory_pool, allocation_size,
                                     MEMORY_TYPE_PINNED, flags,
                                     &memory_handle) == HSA_STATUS_SUCCESS);

  // reserve on host
  const std::uint64_t address = 0;
  const std::uint64_t alignment = 0;
  std::uint32_t *buffer = nullptr;
  REQUIRE(hsa_amd_vmem_address_reserve_align(
              reinterpret_cast<void **>(&buffer), allocation_size, address,
              alignment, flags) == HSA_STATUS_SUCCESS);

  const std::uint64_t offset = 0;
  REQUIRE(hsa_amd_vmem_map(buffer, allocation_size, offset, memory_handle,
                           flags) == HSA_STATUS_SUCCESS);

  std::vector<hsa_amd_memory_access_desc_t> memory_access_desc;
  memory_access_desc.reserve(cpu_agents.size() + gpu_agents.size() +
                             aie_agents.size());
  for (auto const &agent : cpu_agents) {
    memory_access_desc.push_back(
        hsa_amd_memory_access_desc_t{HSA_ACCESS_PERMISSION_RW, agent});
  }
  for (auto const &agent : gpu_agents) {
    memory_access_desc.push_back(
        hsa_amd_memory_access_desc_t{HSA_ACCESS_PERMISSION_RW, agent});
  }
  for (auto const &agent : aie_agents) {
    memory_access_desc.push_back(
        hsa_amd_memory_access_desc_t{HSA_ACCESS_PERMISSION_RW, agent});
  }

  REQUIRE(hsa_amd_vmem_set_access(
              buffer, allocation_size, memory_access_desc.data(),
              memory_access_desc.size()) == HSA_STATUS_SUCCESS);

  REQUIRE(hsa_amd_vmem_unmap(buffer, allocation_size) == HSA_STATUS_SUCCESS);

  REQUIRE(hsa_amd_vmem_address_free(buffer, allocation_size) ==
          HSA_STATUS_SUCCESS);

  REQUIRE(hsa_amd_vmem_handle_release(memory_handle) == HSA_STATUS_SUCCESS);

  REQUIRE(hsa_shut_down() == HSA_STATUS_SUCCESS);
}
