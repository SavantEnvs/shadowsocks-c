#!/usr/bin/env bash
# mayhem/build.sh — builds the shadowsocks-c fuzz targets and the upstream unit-test suite.
#
#   build-mayhem-fuzz/  libFuzzer harnesses + <name>-standalone reproducers (mayhem/CMakeLists.txt
#                       wraps the upstream CMake project; only libshadowsocks-c is instrumented)
#   build-mayhem-afl/   fuzz_jconf, the AFL file-input driver for read_jconf()
#   build-mayhem-test/  upstream's CTest suite (unit + integration) with the project's normal flags
# All three use upstream's bundled dependency mode: every dependency is built from the pinned
# archives in third_party/dist, so the build needs no network. build-*/ is gitignored upstream.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export CC CXX
cd "${SRC:-/mayhem}"

common=(-G Ninja -DBUILD_TESTING=OFF -DSS_BUILD_EXECUTABLES=OFF -DSS_BUILD_SHARED_LIBRARY=OFF
        -DSS_BUILD_STATIC_LIBRARY=ON -DSS_DEPENDENCY_MODE=bundled -DWITH_STATIC=ON
        -DWITH_DOC_MAN=OFF -DWITH_DOC_HTML=OFF -DSS_WARNINGS_AS_ERRORS=OFF)

# 1) libFuzzer harnesses. CMAKE_*_FLAGS (plain debug info, no sanitizers) reach the bundled
#    dependencies; mayhem/CMakeLists.txt adds $SANITIZER_FLAGS + SanCov to libshadowsocks-c and
#    the harnesses, and links mayhem/lsan_off.cc (LeakSanitizer off at build time) into every
#    fuzz and -standalone binary (and fuzz_jconf). A custom build type keeps upstream's Release default (and its -DNDEBUG) out.
cmake -S mayhem -B build-mayhem-fuzz "${common[@]}" \
    -DCMAKE_BUILD_TYPE=Mayhem \
    -DCMAKE_C_FLAGS="-O1 $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="-O1 $DEBUG_FLAGS" \
    -DSS_FUZZ_SAN_FLAGS="$SANITIZER_FLAGS" -DSS_FUZZ_DBG_FLAGS="$DEBUG_FLAGS" \
    -DSS_FUZZ_ENGINE="$LIB_FUZZING_ENGINE" -DSS_FUZZ_STANDALONE="$STANDALONE_FUZZ_MAIN"
cmake --build build-mayhem-fuzz -j"$MAYHEM_JOBS"

# 2) AFL driver for read_jconf (exits on invalid configs, so one process per input).
CC=afl-clang-fast CXX=afl-clang-fast++ AFL_QUIET=1 \
cmake -S mayhem -B build-mayhem-afl "${common[@]}" -DSS_FUZZ_AFL=ON \
    -DCMAKE_BUILD_TYPE=Mayhem \
    -DCMAKE_C_FLAGS="-O1 $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="-O1 $DEBUG_FLAGS" \
    -DSS_FUZZ_SAN_FLAGS="$SANITIZER_FLAGS" -DSS_FUZZ_DBG_FLAGS="$DEBUG_FLAGS"
AFL_QUIET=1 cmake --build build-mayhem-afl -j"$MAYHEM_JOBS" --target fuzz_jconf

# 3) Upstream test suite, normal flags (Release; the tests keep their asserts with -UNDEBUG).
#    SS_BUILD_EXECUTABLES=ON builds ss-server/ss-local/ss-tunnel/ss-manager/ss-redir as well, which
#    registers upstream's integration tests (tests/CMakeLists.txt) that mayhem/test.sh runs via ctest.
cmake -S . -B build-mayhem-test "${common[@]}" -DBUILD_TESTING=ON -DSS_BUILD_EXECUTABLES=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-mayhem-test -j"$MAYHEM_JOBS"
