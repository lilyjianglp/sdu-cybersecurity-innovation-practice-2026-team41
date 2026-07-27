cmake_minimum_required(VERSION 3.16)
project(aes128_optimization C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(AES128_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

function(aes128_apply_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
endfunction()

function(aes128_apply_sanitizers target)
    if(AES128_ENABLE_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer
        )
        target_link_options(${target} PRIVATE
            -fsanitize=address,undefined
        )
    endif()
endfunction()

add_library(aes128_core STATIC
    src/aes128_ref.c
    src/aes128_ttable.c
    src/aes128_avx2.c
    src/aes128_aesni.c
    src/aes128_ctr.c
    src/aes128_gcm.c
    src/aes128_xts.c
)
target_include_directories(aes128_core PUBLIC include)
aes128_apply_warnings(aes128_core)
aes128_apply_sanitizers(aes128_core)

add_executable(test_aes128 tests/test_aes128.c)
target_link_libraries(test_aes128 PRIVATE aes128_core)
aes128_apply_warnings(test_aes128)
aes128_apply_sanitizers(test_aes128)

add_executable(bench_aes128 bench/bench_aes128.c)
target_link_libraries(bench_aes128 PRIVATE aes128_core)
target_compile_options(bench_aes128 PRIVATE -O3)
aes128_apply_warnings(bench_aes128)
aes128_apply_sanitizers(bench_aes128)

add_executable(test_aes128_ttable tests/test_aes128_ttable.c)
target_link_libraries(test_aes128_ttable PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_ttable)
aes128_apply_sanitizers(test_aes128_ttable)

add_executable(bench_aes128_compare bench/bench_aes128_compare.c)
target_link_libraries(bench_aes128_compare PRIVATE aes128_core)
target_compile_options(bench_aes128_compare PRIVATE -O3)
aes128_apply_warnings(bench_aes128_compare)
aes128_apply_sanitizers(bench_aes128_compare)

add_executable(test_aes128_avx2 tests/test_aes128_avx2.c)
target_link_libraries(test_aes128_avx2 PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_avx2)
aes128_apply_sanitizers(test_aes128_avx2)

add_executable(bench_aes128_phase3 bench/bench_aes128_phase3.c)
target_link_libraries(bench_aes128_phase3 PRIVATE aes128_core)
target_compile_options(bench_aes128_phase3 PRIVATE -O3)
aes128_apply_warnings(bench_aes128_phase3)
aes128_apply_sanitizers(bench_aes128_phase3)

add_executable(test_aes128_aesni tests/test_aes128_aesni.c)
target_link_libraries(test_aes128_aesni PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_aesni)
aes128_apply_sanitizers(test_aes128_aesni)

add_executable(bench_aes128_phase4 bench/bench_aes128_phase4.c)
target_link_libraries(bench_aes128_phase4 PRIVATE aes128_core)
target_compile_options(bench_aes128_phase4 PRIVATE -O3)
aes128_apply_warnings(bench_aes128_phase4)
aes128_apply_sanitizers(bench_aes128_phase4)

add_executable(test_aes128_ctr tests/test_aes128_ctr.c)
target_link_libraries(test_aes128_ctr PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_ctr)
aes128_apply_sanitizers(test_aes128_ctr)

add_executable(bench_aes128_ctr bench/bench_aes128_ctr.c)
target_link_libraries(bench_aes128_ctr PRIVATE aes128_core)
target_compile_options(bench_aes128_ctr PRIVATE -O3)
aes128_apply_warnings(bench_aes128_ctr)
aes128_apply_sanitizers(bench_aes128_ctr)

add_executable(test_aes128_gcm tests/test_aes128_gcm.c)
target_link_libraries(test_aes128_gcm PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_gcm)
aes128_apply_sanitizers(test_aes128_gcm)

add_executable(bench_aes128_gcm bench/bench_aes128_gcm.c)
target_link_libraries(bench_aes128_gcm PRIVATE aes128_core)
target_compile_options(bench_aes128_gcm PRIVATE -O3)
aes128_apply_warnings(bench_aes128_gcm)
aes128_apply_sanitizers(bench_aes128_gcm)

add_executable(test_aes128_xts tests/test_aes128_xts.c)
target_link_libraries(test_aes128_xts PRIVATE aes128_core)
aes128_apply_warnings(test_aes128_xts)
aes128_apply_sanitizers(test_aes128_xts)

add_executable(bench_aes128_xts bench/bench_aes128_xts.c)
target_link_libraries(bench_aes128_xts PRIVATE aes128_core)
target_compile_options(bench_aes128_xts PRIVATE -O3)
aes128_apply_warnings(bench_aes128_xts)
aes128_apply_sanitizers(bench_aes128_xts)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME aes128_reference_vectors COMMAND test_aes128)
    add_test(NAME aes128_ttable_crosscheck COMMAND test_aes128_ttable)
    add_test(NAME aes128_avx2_crosscheck COMMAND test_aes128_avx2)
    add_test(NAME aes128_aesni_crosscheck COMMAND test_aes128_aesni)
    add_test(NAME aes128_ctr_vectors COMMAND test_aes128_ctr)
    add_test(NAME aes128_gcm_vectors COMMAND test_aes128_gcm)
    add_test(NAME aes128_xts_vectors COMMAND test_aes128_xts)
endif()
