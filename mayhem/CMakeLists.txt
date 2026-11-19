# Mayhem fuzz build: wraps the upstream project unchanged (add_subdirectory) and adds the harnesses.
#
# Only the project's own library (shadowsocks-c-static) is instrumented with the sanitizers and
# SanCov; the bundled third-party code (libsodium, mbedtls, c-ares, libuv, pcre2, bloom, blake3)
# keeps the plain debug flags from CMAKE_C_FLAGS, so the fuzzer explores shadowsocks-c itself.
#
#   SS_FUZZ_SAN_FLAGS  sanitizer flags for the project + harnesses ($SANITIZER_FLAGS; may be empty)
#   SS_FUZZ_DBG_FLAGS  debug flags ($DEBUG_FLAGS, DWARF <= 3)
#   SS_FUZZ_ENGINE     libFuzzer link flag ($LIB_FUZZING_ENGINE)
#   SS_FUZZ_STANDALONE run-once driver ($STANDALONE_FUZZ_MAIN)
#   SS_FUZZ_AFL        ON: build only the AFL file-input driver(s) (CC/CXX = afl-clang-fast)
cmake_minimum_required(VERSION 3.20)
project(shadowsocks_c_mayhem LANGUAGES C CXX)

set(SS_FUZZ_SAN_FLAGS "" CACHE STRING "")
set(SS_FUZZ_DBG_FLAGS "-g -gdwarf-3" CACHE STRING "")
set(SS_FUZZ_ENGINE "-fsanitize=fuzzer" CACHE STRING "")
set(SS_FUZZ_STANDALONE "" CACHE FILEPATH "")
option(SS_FUZZ_AFL "Build the AFL drivers instead of the libFuzzer harnesses" OFF)
separate_arguments(SAN UNIX_COMMAND "${SS_FUZZ_SAN_FLAGS}")
separate_arguments(DBG UNIX_COMMAND "${SS_FUZZ_DBG_FLAGS}")
separate_arguments(ENGINE UNIX_COMMAND "${SS_FUZZ_ENGINE}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)
set(SS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
add_subdirectory(${SS_ROOT} ss)
set(SS_BIN ${CMAKE_BINARY_DIR}/ss)

add_compile_definitions(HAVE_CONFIG_H _GNU_SOURCE)
set(OUT ${CMAKE_BINARY_DIR}/out)

if(SS_FUZZ_AFL)
    # read_jconf() calls FATAL() -> exit(-1) on any invalid config, so it is fuzzed as a file-input
    # AFL target (one process per input) instead of in-process.
    add_executable(fuzz_jconf
        fuzz/jconf_main.cpp lsan_off.cc
        ${SS_ROOT}/src/jconf.cpp ${SS_ROOT}/src/json.cpp ${SS_ROOT}/src/utils.cpp ${SS_ROOT}/src/netutils.cpp)
    target_include_directories(fuzz_jconf PRIVATE ${SS_ROOT}/src ${SS_BIN}/src)
    target_compile_options(fuzz_jconf PRIVATE ${SAN} ${DBG})
    target_link_options(fuzz_jconf PRIVATE ${SAN} ${DBG})
    target_link_libraries(fuzz_jconf PRIVATE ss_sodium ss_ev ss_cares ss_mbedcrypto Threads::Threads m)
    set_target_properties(fuzz_jconf PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${OUT})
    return()
endif()

# Instrument the project library (not its bundled dependencies).
target_compile_options(shadowsocks-c-static PRIVATE ${SAN} -fsanitize=fuzzer-no-link ${DBG})

add_library(ss_standalone_main OBJECT ${SS_FUZZ_STANDALONE})
set_source_files_properties(${SS_FUZZ_STANDALONE} PROPERTIES LANGUAGE C)
target_compile_options(ss_standalone_main PRIVATE ${SAN} ${DBG})

function(ss_fuzzer name)
    foreach(variant fuzz standalone)
        if(variant STREQUAL "fuzz")
            set(exe ${name})
            set(extra_c ${ENGINE})
            set(extra_src)
        else()
            set(exe ${name}-standalone)
            set(extra_c)
            set(extra_src $<TARGET_OBJECTS:ss_standalone_main>)
        endif()
        add_executable(${exe} fuzz/${name}.cpp lsan_off.cc ${extra_src})
        target_include_directories(${exe} PRIVATE ${SS_ROOT}/src ${SS_BIN}/src ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
        target_compile_options(${exe} PRIVATE ${SAN} ${DBG} ${extra_c})
        target_link_options(${exe} PRIVATE ${SAN} ${DBG} ${extra_c})
        target_link_libraries(${exe} PRIVATE shadowsocks-c-static ss_sodium ss_mbedcrypto ss_cares ss_ev
                              blake3 bloom Threads::Threads m ${ARGN})
        set_target_properties(${exe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${OUT})
    endforeach()
endfunction()

ss_fuzzer(fuzz_json)
ss_fuzzer(fuzz_ssurl)
ss_fuzzer(fuzz_acl ss_pcre2)
ss_fuzzer(fuzz_aead_tcp)
ss_fuzzer(fuzz_aead2022_tcp)
ss_fuzzer(fuzz_udp)
ss_fuzzer(fuzz_socks_addr)
