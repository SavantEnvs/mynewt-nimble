#!/usr/bin/env bash
#
# mayhem/build.sh — NimBLE host stack, fuzzed through a fake controller (mayhem/nimble_env.c).
#
# Builds, from the upstream sources as upstream's own Linux NPL port compiles them (no controller, no LL):
#   1. the host library with $SANITIZER_FLAGS + SanCov (instrumented fuzzed code)  -> mayhem/build-fuzz/
#   2. every harness twice: libFuzzer binary and -standalone reproducer             -> /mayhem/<name>[-standalone]
#   3. the behavioural oracle (mayhem/selftest.c) against a separate, NORMAL-flags library build
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Include path: mayhem/include comes first so its nimble_npl_os_log.h (which drops host log output —
# printing from the fuzzed code only costs throughput) wins over the NPL port's.
INC="-Imayhem/include -Imayhem -Inimble/host/src -Iporting/examples/linux/include -Iporting/npl/linux/include
 -Inimble/include -Inimble/host/include -Inimble/host/util/include -Inimble/host/store/config/include
 -Inimble/transport/include -Iporting/nimble/include"
for s in ans bas gap gatt ias dis lls tps; do INC="$INC -Inimble/host/services/$s/include"; done
INC=$(echo $INC)

# syscfg overrides: no controller, so HCI commands are acknowledged synchronously (PHONY_HCI_ACKS);
# secure connections on; two connections / two CoC channels keep the pools small and fast.
DEFS="-D_GNU_SOURCE -DMYNEWT_VAL_BLE_HS_PHONY_HCI_ACKS=1 -DMYNEWT_VAL_BLE_SM_SC=1
 -DMYNEWT_VAL_BLE_MAX_CONNECTIONS=2 -DMYNEWT_VAL_BLE_L2CAP_COC_MAX_NUM=2"
DEFS=$(echo $DEFS)

# Host stack + Linux NPL port. The LL socket transport, hal timer and cputime sources are not used: the
# fake controller in nimble_env.c implements the transport hooks and the NPL port provides the timers.
CSRCS=$(ls porting/nimble/src/*.c nimble/host/src/*.c nimble/host/util/src/*.c \
           nimble/host/services/{ans,bas,gap,gatt,dis,ias,lls,tps}/src/*.c \
           nimble/host/store/config/src/*.c nimble/transport/src/*.c porting/npl/linux/src/*.c \
        | grep -v 'hal_timer\|os_cputime')
CXXSRCS=$(ls porting/npl/linux/src/*.cc)
MBEDCRYPTO="-l:libmbedcrypto.a"
SYSLIBS="-lstdc++ -lrt -lpthread -lm"

# build_lib <outdir> <flags...>  — compile every source into <outdir>/*.o and archive libnimble.a
build_lib() {
    local out="$1"; shift
    rm -rf "$out"; mkdir -p "$out"
    {
        for f in $CSRCS; do
            extra=""
            # Upstream ble_l2cap_sig_reject_tx() does memcpy(cmd->data, NULL, 0) on an unknown signaling
            # opcode — benign UB that would abort every such input; relaxed for this one file only.
            case "$f" in */ble_l2cap_sig_cmd.c) extra="-fno-sanitize=nonnull-attribute";; esac
            echo "$CC $* $extra -O1 $INC $DEFS -w -c $f -o $out/$(echo "$f" | tr / _).o"
        done
        for f in $CXXSRCS; do
            echo "$CXX $* -O1 $INC $DEFS -w -c $f -o $out/$(echo "$f" | tr / _).o"
        done
    } | xargs -P "$MAYHEM_JOBS" -I{} sh -c "{}"
    rm -f "$out/libnimble.a"
    ar rcs "$out/libnimble.a" "$out"/*.o
}

# 1) Instrumented host library. -fsanitize=fuzzer-no-link adds SanCov to the library itself; without it
#    the harness would only cover its own few lines and Mayhem would see no edges in the host stack.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
build_lib mayhem/build-fuzz $FUZZ_CFLAGS

$CC $FUZZ_CFLAGS -O1 $INC $DEFS -Wall -c mayhem/nimble_env.c -o mayhem/build-fuzz/nimble_env.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/build-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/standalone_main.o

# 2) Harnesses: fuzz binary + standalone (run-once) reproducer.
for h in fuzz_acl fuzz_hci_evt fuzz_adv_data fuzz_uuid; do
    $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $INC $DEFS -c "mayhem/$h.c" -o "mayhem/build-fuzz/$h.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "mayhem/build-fuzz/$h.o" mayhem/build-fuzz/nimble_env.o \
        mayhem/build-fuzz/lsan_off.o mayhem/build-fuzz/libnimble.a $MBEDCRYPTO $SYSLIBS -o "$SRC/$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "mayhem/build-fuzz/$h.o" mayhem/build-fuzz/standalone_main.o mayhem/build-fuzz/nimble_env.o \
        mayhem/build-fuzz/lsan_off.o mayhem/build-fuzz/libnimble.a $MBEDCRYPTO $SYSLIBS -o "$SRC/$h-standalone"
done

# 3) Test oracle: plain build of the same sources — no sanitizers, no SanCov, normal optimisation.
build_lib mayhem/build-test $COVERAGE_FLAGS
$CC -O2 $COVERAGE_FLAGS $INC $DEFS -Wall -c mayhem/nimble_env.c -o mayhem/build-test/nimble_env.o
$CC -O2 $COVERAGE_FLAGS $INC $DEFS -Wall -c mayhem/selftest.c -o mayhem/build-test/selftest.o
$CC $COVERAGE_FLAGS mayhem/build-test/selftest.o mayhem/build-test/nimble_env.o mayhem/build-test/libnimble.a $MBEDCRYPTO $SYSLIBS \
    -o "$SRC/nimble_selftest"
