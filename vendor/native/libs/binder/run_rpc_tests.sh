#!/usr/bin/env bash

set -ex

if [ $# -eq 0 ]; then
  :
elif [ $# -eq 1 ] && [[ "$1" =~ ^host|device$ ]]; then
  :
else
  echo "usage: $0 [device|host]"
  false
fi

# Script maintained for RPC development, while it is active, to quickly run
# tests. Generally, to match VTS/presubmit behavior, 'atest' should be used.

function dtest () { adb shell /data/nativetest64/$1/$@; }
function hbench () { $AT/out/host/linux-x86/benchmarktest/$1/$@; }
function hfuzz () { time $ANDROID_HOST_OUT/fuzz/x86_64/$1/$@; }
function htest () { time $ANDROID_BUILD_TOP/out/host/linux-x86/nativetest/$1/$@; }
function pdtest () { adb wait-for-device && adb shell mkdir -p /data/nativetest64/$1 && adb push $OUT/data/nativetest64/$1/$1 /data/nativetest64/$1/$1 && dtest $@; }
function dbench () { adb shell /data/benchmarktest64/$1/$@; }
function pdbench () { adb wait-for-device && adb shell mkdir -p /data/benchmarktest64/$1 && adb push $OUT/data/benchmarktest64/$1/$1 /data/benchmarktest64/$1/$1 && dbench $@; }

$ANDROID_BUILD_TOP/build/soong/soong_ui.bash --make-mode \
  binderRpcTest \
  binder_rpc_fuzzer \
  binder_parcel_fuzzer \
  binderLibTest \
  binderRpcBenchmark

if ! [ "$1" = "device" ]; then
  htest binderRpcTest
  hbench binderRpcBenchmark
  hfuzz binder_rpc_fuzzer -max_total_time=30
  hfuzz binder_parcel_fuzzer -max_total_time=30
fi

if ! [ "$1" = "host" ]; then
  pdtest binderRpcTest
  pdtest binderLibTest
  pdbench binderRpcBenchmark
fi

