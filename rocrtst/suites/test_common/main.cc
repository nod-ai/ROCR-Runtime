/*
 * =============================================================================
 *   ROC Runtime Conformance Release License
 * =============================================================================
 * The University of Illinois/NCSA
 * Open Source License (NCSA)
 *
 * Copyright (c) 2017, Advanced Micro Devices, Inc.
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

#include <string>
#include <vector>
#include <memory>

#include "gtest/gtest.h"
#include "suites/functional/debug_basic.h"
#include "suites/functional/memory_basic.h"
#include "suites/functional/memory_access.h"
#include "suites/functional/ipc.h"
#include "suites/functional/memory_alignment.h"
#include "suites/functional/memory_atomics.h"
#include "suites/performance/dispatch_time.h"
#include "suites/performance/memory_async_copy.h"
#include "suites/performance/memory_async_copy_numa.h"
#include "suites/performance/enqueueLatency.h"
#include "suites/negative/memory_allocate_negative_tests.h"
#include "suites/negative/queue_validation.h"
#include "suites/stress/memory_concurrent_tests.h"
#include "suites/test_common/test_case_template.h"
#include "suites/test_common/main.h"
#include "suites/test_common/test_common.h"
#include "suites/functional/concurrent_init.h"
#include "suites/functional/concurrent_init_shutdown.h"
#include "suites/functional/concurrent_shutdown.h"
#include "suites/functional/reference_count.h"
#include "rocm_smi/rocm_smi.h"

static RocrTstGlobals *sRocrtstGlvalues = nullptr;

static void SetFlags(TestBase *test) {
  assert(sRocrtstGlvalues != nullptr);

  test->set_num_iteration(sRocrtstGlvalues->num_iterations);
  test->set_verbosity(sRocrtstGlvalues->verbosity);
  test->set_monitor_verbosity(sRocrtstGlvalues->monitor_verbosity);
}

static void RunCustomTestProlog(TestBase *test) {
  SetFlags(test);

  test->DisplayTestInfo();
  test->SetUp();
  test->Run();
  return;
}
static void RunCustomTestEpilog(TestBase *test) {
  test->DisplayResults();
  test->Close();
  return;
}

// If the test case one big test, you should use RunGenericTest()
// to run the test case. OTOH, if the test case consists of multiple
// functions to be run as separate tests, follow this pattern:
//   * RunCustomTestProlog(test)  // Run() should contain minimal code
//   * <insert call to actual test function within test case>
//   * RunCustomTestEpilog(test)
static void RunGenericTest(TestBase *test) {
  RunCustomTestProlog(test);
  RunCustomTestEpilog(test);
  return;
}

// TEST ENTRY TEMPLATE:
// TEST(rocrtst, Perf_<test name>) {
//  <Test Implementation class> <test_obj>;
//
//  // Copy and modify implementation of RunGenericTest() if you need to deviate
//  // from the standard pattern implemented there.
//  RunGenericTest(&<test_obj>);
// }

TEST(rocrtst, Test_Example) {
  TestExample tst;

  RunGenericTest(&tst);
}

TEST(rocrtstFunc, IPC) {
  IPCTest ipc;
  RunGenericTest(&ipc);
}

TEST(rocrtstFunc, MemoryAccessTests) {
  MemoryAccessTest mt;
  RunCustomTestProlog(&mt);
  mt.CPUAccessToGPUMemoryTest();
  mt.GPUAccessToCPUMemoryTest();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstFunc, Concurrent_Init_Test) {
  ConcurrentInitTest ci;
  RunCustomTestProlog(&ci);
  ci.TestConcurrentInit();
  RunCustomTestEpilog(&ci);
}

TEST(rocrtstFunc, Concurrent_Init_Shutdown_Test) {
  ConcurrentInitShutdownTest ci;
  RunCustomTestProlog(&ci);
  ci.TestConcurrentInitShutdown();
  RunCustomTestEpilog(&ci);
}
TEST(rocrtstFunc, Concurrent_Shutdown) {
  ConcurrentShutdownTest cs;
  RunCustomTestProlog(&cs);
  cs.TestConcurrentShutdown();
  RunCustomTestEpilog(&cs);
}


TEST(rocrtstFunc, Reference_Count) {
  ReferenceCountTest rc(true, false);
  RunCustomTestProlog(&rc);
  rc.TestReferenceCount();
  RunCustomTestEpilog(&rc);
}

TEST(rocrtstFunc, Max_Reference_Count) {
  ReferenceCountTest rc(false, true);
  RunCustomTestProlog(&rc);
  rc.TestMaxReferenceCount();
  RunCustomTestEpilog(&rc);
}

TEST(rocrtstFunc, Memory_Max_Mem) {
  MemoryTest mt;

  RunCustomTestProlog(&mt);
  mt.MaxSingleAllocationTest();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstFunc, Memory_Atomic_Add_Test) {
  MemoryAtomic ma(ADD);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Sub_Test) {
  MemoryAtomic ma(SUB);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_And_Test) {
  MemoryAtomic ma(AND);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Or_Test) {
  MemoryAtomic ma(OR);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Xor_Test) {
  MemoryAtomic ma(XOR);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Min_Test) {
  MemoryAtomic ma(MIN);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Max_Test) {
  MemoryAtomic ma(MAX);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Inc_Test) {
  MemoryAtomic ma(INC);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Dec_Test) {
  MemoryAtomic ma(DEC);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, Memory_Atomic_Xchg_Test) {
  MemoryAtomic ma(XCHG);
  RunCustomTestProlog(&ma);
  ma.MemoryAtomicTest();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstFunc, DebugBasicTests) {
  DebugBasicTest mt;
  RunCustomTestProlog(&mt);
  mt.VectorAddDebugTrapTest();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstFunc, Memory_Alignment_Test) {
  MemoryAlignmentTest ma;
  RunCustomTestProlog(&ma);
  ma.MemoryPoolAlignment();
  RunCustomTestEpilog(&ma);
}

TEST(rocrtstNeg, Memory_Negative_Tests) {
  MemoryAllocateNegativeTest mt;
  RunCustomTestProlog(&mt);
  mt.ZeroMemoryAllocateTest();
  mt.MaxMemoryAllocateTest();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstNeg, Queue_Validation_InvalidDimension) {
  QueueValidation qv(true, false, false, false, false);
  RunCustomTestProlog(&qv);
  qv.QueueValidationForInvalidDimension();
  RunCustomTestEpilog(&qv);
}

TEST(rocrtstNeg, Queue_Validation_InvalidGroupMemory) {
  QueueValidation qv(false, true, false, false, false);
  RunCustomTestProlog(&qv);
  qv.QueueValidationInvalidGroupMemory();
  RunCustomTestEpilog(&qv);
}

TEST(rocrtstNeg, Queue_Validation_InvalidKernelObject) {
  QueueValidation qv(false, false, true, false, false);
  RunCustomTestProlog(&qv);
  qv.QueueValidationForInvalidKernelObject();
  RunCustomTestEpilog(&qv);
}

TEST(rocrtstNeg, Queue_Validation_InvalidPacket) {
  QueueValidation qv(false, false, false, true, false);
  RunCustomTestProlog(&qv);
  qv.QueueValidationForInvalidPacket();
  RunCustomTestEpilog(&qv);
}

TEST(rocrtstNeg, Queue_Validation_InvalidWorkGroupSize) {
  QueueValidation qv(false, false, false, false, true);
  RunCustomTestProlog(&qv);
  qv.QueueValidationForInvalidWorkGroupSize();
  RunCustomTestEpilog(&qv);
}

TEST(rocrtstStress, Memory_Concurrent_Allocate_Test) {
  MemoryConcurrentTest mt(true, false, false);
  RunCustomTestProlog(&mt);
  mt.MemoryConcurrentAllocate();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstStress, Memory_Concurrent_Free_Test) {
  MemoryConcurrentTest mt(false, true, false);
  RunCustomTestProlog(&mt);
  mt.MemoryConcurrentFree();
  RunCustomTestEpilog(&mt);
}

TEST(rocrtstStress, DISABLED_Memory_Concurrent_Pool_Info_Test) {
  MemoryConcurrentTest mt(false, false, true);
  RunCustomTestProlog(&mt);
  mt.MemoryConcurrentPoolGetInfo();
  RunCustomTestEpilog(&mt);
}
TEST(rocrtstPerf, ENQUEUE_LATENCY) {
  EnqueueLatency singlePacketequeue(true);
  EnqueueLatency multiPacketequeue(false);
  RunGenericTest(&singlePacketequeue);
  RunGenericTest(&multiPacketequeue);
}

TEST(rocrtstPerf, Memory_Async_Copy) {
  MemoryAsyncCopy mac;
  // To do full test, uncomment this:
  //  mac.set_full_test(true);
  // To test only 1 path, add lines like this:
  //  mac.set_src_pool(<src pool id>);
  //  mac.set_dst_pool(<dst pool id>);
  // The default is to and from the cpu to 1 gpu, and to/from a gpu to
  // another gpu
  RunGenericTest(&mac);
}

TEST(rocrtstPerf, Memory_Async_Copy_NUMA) {
  MemoryAsyncCopyNUMA numa;
  RunGenericTest(&numa);
}

TEST(rocrtstPerf, AQL_Dispatch_Time_Single_SpinWait) {
  DispatchTime dt(true, true);
  RunGenericTest(&dt);
}

TEST(rocrtstPerf, AQL_Dispatch_Time_Single_Interrupt) {
  DispatchTime dt(false, true);
  RunGenericTest(&dt);
}

TEST(rocrtstPerf, AQL_Dispatch_Time_Multi_SpinWait) {
  DispatchTime dt(true, false);
  RunGenericTest(&dt);
}

TEST(rocrtstPerf, AQL_Dispatch_Time_Multi_Interrupt) {
  DispatchTime dt(false, false);
  RunGenericTest(&dt);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  RocrTstGlobals settings;

  // Set some default values
  settings.verbosity = 1;
  settings.monitor_verbosity = 1;
  settings.num_iterations = 5;

  if (ProcessCmdline(&settings, argc, argv)) {
    return 1;
  }
  sRocrtstGlvalues = &settings;
  rsmi_status_t rsmi_ret = rsmi_init(0);
  if (rsmi_ret != RSMI_STATUS_SUCCESS) {
    std::cout << "Failed to initialize ROCm smi" << std::endl;
    return 1;
  }
  DumpMonitorInfo();

  return RUN_ALL_TESTS();
}
