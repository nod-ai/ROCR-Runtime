include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.5.4
)
FetchContent_MakeAvailable(Catch2)

find_package(hsa-runtime64 CONFIG REQUIRED NAMES hsa_runtime64 hsa-runtime64)

# smoke test
add_executable(aie_hsa_bare_add_one aie_hsa_bare_add_one.cc)

# hsa test
add_executable(aie_hsa_dispatch_test aie_hsa_dispatch_test.cc)
target_link_libraries(aie_hsa_dispatch_test PRIVATE hsa-runtime64::hsa-runtime64)

# memory test
add_executable(memory memory.cc)
set_target_properties(memory
  PROPERTIES
    CXX_STANDARD                17
    CXX_EXTENSIONS              OFF
    CXX_VISIBILITY_PRESET       hidden
    VISIBILITY_INLINES_HIDDEN   ON
    POSITION_INDEPENDENT_CODE   ON
)
target_compile_options(memory
  PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
target_link_libraries(memory
  PRIVATE
    hsa-runtime64::hsa-runtime64
    Catch2::Catch2WithMain
)
