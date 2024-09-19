#find_package(hsa-runtime64 CONFIG REQUIRED NAMES hsa_runtime64 hsa-runtime64)

# smoke test
add_executable(aie_hsa_test_bare_add_one aie_hsa_test_bare_add_one.cc)

# hsa test
add_executable(aie_hsa_test_dispatch aie_hsa_test_dispatch.cc)
target_link_libraries(aie_hsa_test_dispatch PUBLIC hsa-runtime64)
