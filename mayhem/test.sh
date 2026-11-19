#!/usr/bin/env bash
#
# mayhem/test.sh — RUN shadowsocks-c's own CTest suite: the unit binaries (built by mayhem/build.sh into
# build-mayhem-test/bin with the project's normal flags), then the integration tests via ctest. PATCH-grade oracle: after an agent patches
# the source, the grader rebuilds (build.sh) then runs this.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/build-mayhem-test/bin"
shopt -s nullglob
tests=("$BIN"/test_*)
if [ "${#tests[@]}" -lt 25 ]; then
  echo "test.sh: expected the unit-test binaries in $BIN (found ${#tests[@]}) — build.sh did not build them" >&2
  emit_ctrf "shadowsocks-c-unit" 0 1 0
  exit 1
fi

# Part 1 — unit binaries. Every unit test checks known answers with SS_CHECK (abort on mismatch)
# and prints "ok <case>" after each case passes (tests/test_helpers.hpp). A binary passes iff it
# exits 0 AND reports at least one "ok" line; each "ok" line is counted as a passed case, a failing
# binary as one failure. (ctest alone only sees exit codes, which a no-op _exit(0) would satisfy.)
ulimit -n 1024 2>/dev/null || true
passed=0 failed=0 skipped=0
names=()
cd "$BIN"
for t in "${tests[@]}"; do
  name=$(basename "$t")
  names+=("$name")
  out=$(timeout 120 "$t" 2>&1); rc=$?
  oks=$(printf '%s\n' "$out" | grep -c '^ok ' || true)
  if [ "$rc" -eq 0 ] && [ "$oks" -gt 0 ]; then
    passed=$((passed + oks))
    echo "PASS $name ($oks cases)"
  else
    failed=$((failed + 1))
    echo "FAIL $name (exit $rc, $oks ok lines)"
    printf '%s\n' "$out" | tail -20
  fi
done
cd "$SRC"

# Part 2 — the rest of upstream's CTest suite, as upstream CI runs it (`ctest -LE memcheck`):
# the Python integration tests that drive the real ss-server/ss-local/ss-tunnel/ss-manager over
# loopback (test_cli, test_limits, test_server_acl, test_half_close, test_tunnel_interop,
# test_manager, test_udp_session_eviction, test_printable_salt_interop, ...), the alloc_steady_*
# zero-allocation audits, check_no_heap, check_cxx_runtime, test_ss_setup and the bundled
# libsodium known-answer tests. The unit binaries above are excluded so they are not counted twice.
# test_interop_rust exits 77 (CTest SKIP_RETURN_CODE) without shadowsocks-rust: counted as skipped.
# memcheck tests are only registered when valgrind is installed (it is not in the image).
command -v python3 >/dev/null || { echo "test.sh: python3 missing — the integration tests need it" >&2; failed=$((failed + 1)); }
exclude="^($(IFS='|'; echo "${names[*]}"))\$"
junit=$(mktemp "${TMPDIR:-/tmp}/ss-ctest.XXXXXX.xml")
ctest --test-dir build-mayhem-test -LE memcheck -E "$exclude" -j"$MAYHEM_JOBS" \
      --output-on-failure --no-tests=error --output-junit "$junit"
crc=$?
read -r cp cf cs < <(python3 -I - "$junit" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    cases = ET.parse(sys.argv[1]).getroot().iter("testcase")
except Exception:
    print(0, 1, 0); sys.exit()
p = f = s = 0
for c in cases:
    st = c.get("status", "")
    if c.find("failure") is not None or c.find("error") is not None or st == "fail":
        f += 1
    elif c.find("skipped") is not None or st in ("disabled", "notrun"):
        s += 1
    else:
        p += 1
print(p, f, s)
PY
)
rm -f "$junit"
# A non-zero ctest exit with no failure parsed (e.g. no tests found) still fails the oracle.
if [ "$crc" -ne 0 ] && [ "${cf:-0}" -eq 0 ]; then cf=1; fi
if [ "$(( ${cp:-0} + ${cf:-0} + ${cs:-0} ))" -lt 30 ]; then
  echo "test.sh: expected the integration tests to be registered (got ${cp:-0}+${cf:-0}+${cs:-0}) — build.sh must set SS_BUILD_EXECUTABLES=ON" >&2
  cf=$(( ${cf:-0} + 1 ))
fi
echo "ctest: ${cp:-0} passed, ${cf:-0} failed, ${cs:-0} skipped"
passed=$((passed + ${cp:-0})) failed=$((failed + ${cf:-0})) skipped=$((skipped + ${cs:-0}))
emit_ctrf "shadowsocks-c-ctest" "$passed" "$failed" "$skipped"
