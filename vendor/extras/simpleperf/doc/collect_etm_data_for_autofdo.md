# Collect ETM data for AutoFDO

[TOC]

## Introduction

ETM is a hardware feature available on arm64 devices. It collects the instruction stream running on
each cpu. ARM uses ETM as an alternative for LBR (last branch record) on x86.
Simpleperf supports collecting ETM data, and converting it to input files for AutoFDO, which can
then be used for PGO (profile-guided optimization) during compilation.

On ARMv8, ETM is considered as an external debug interface (unless ARMv8.4 Self-hosted Trace
extension is impelemented). So it needs to be enabled explicitly in the bootloader, and isn't
available on user devices. For Pixel devices, it's available on EVT and DVT devices on Pixel 4,
Pixel 4a (5G) and Pixel 5. To test if it's available on other devices, you can follow commands in
this doc and see if you can record any ETM data.

## Examples

Below are examples collecting ETM data for AutoFDO. It has two steps: first recording ETM data,
second converting ETM data to AutoFDO input files.

Record ETM data:

```sh
# preparation: we need to be root to record ETM data
$ adb root
$ adb shell
redfin:/ \# cd data/local/tmp
redfin:/data/local/tmp \#

# Do a system wide collection, it writes output to perf.data.
# If only want ETM data for kernel, use `-e cs-etm:k`.
# If only want ETM data for userspace, use `-e cs-etm:u`.
redfin:/data/local/tmp \# simpleperf record -e cs-etm --duration 3 -a

# To reduce file size and time converting to AutoFDO input files, we recommend converting ETM data
# into an intermediate branch-list format.
redfin:/data/local/tmp \# simpleperf inject --output branch-list -o branch_list.data
```

Converting ETM data to AutoFDO input files needs to read binaries.
So for userspace libraries, they can be converted on device. For kernel, it needs
to be converted on host, with vmlinux and kernel modules available.

Convert ETM data for userspace libraries:

```sh
# Injecting ETM data on device. It writes output to perf_inject.data.
# perf_inject.data is a text file, containing branch counts for each library.
redfin:/data/local/tmp \# simpleperf inject -i branch_list.data
```

Convert ETM data for kernel:

```sh
# pull ETM data to host.
host $ adb pull /data/local/tmp/branch_list.data
# download vmlinux and kernel modules to <binary_dir>
# host simpleperf is in <aosp-top>/system/extras/simpleperf/scripts/bin/linux/x86_64/simpleperf,
# or you can build simpleperf by `mmma system/extras/simpleperf`.
host $ simpleperf inject --symdir <binary_dir> -i branch_list.data
```

The generated perf_inject.data may contain branch info for multiple binaries. But AutoFDO only
accepts one at a time. So we need to split perf_inject.data.
The format of perf_inject.data is below:

```perf_inject.data format

executed range with count info for binary1
branch with count info for binary1
// name for binary1

executed range with count info for binary2
branch with count info for binary2
// name for binary2

...
```

We need to split perf_inject.data, and make sure one file only contains info for one binary.

Then we can use [AutoFDO](https://github.com/google/autofdo) to create profile. AutoFDO only works
for binaries having an executable segment as its first loadable segment. But binaries built in
Android may not follow this rule. Simpleperf inject command knows how to work around this problem.
But there is a check in AutoFDO forcing binaries to start with an executable segment. We need to
disable the check in AutoFDO, by commenting out L127-L136 in
https://github.com/google/autofdo/commit/188db2834ce74762ed17108ca344916994640708#diff-2d132ecbb5e4f13e0da65419f6d1759dd27d6b696786dd7096c0c34d499b1710R127-R136.
Then we can use `create_llvm_prof` in AutoFDO to create profiles used by clang.

```sh
# perf_inject_binary1.data is split from perf_inject.data, and only contains branch info for binary1.
host $ autofdo/create_llvm_prof -profile perf_inject_binary1.data -profiler text -binary path_of_binary1 -out a.prof -format binary

# perf_inject_kernel.data is split from perf_inject.data, and only contains branch info for [kernel.kallsyms].
host $ autofdo/create_llvm_prof -profile perf_inject_kernel.data -profiler text -binary vmlinux -out a.prof -format binary
```

Then we can use a.prof for PGO during compilation, via `-fprofile-sample-use=a.prof`.
[Here](https://clang.llvm.org/docs/UsersManual.html#using-sampling-profilers) are more details.

### A complete example: etm_test_loop.cpp

`etm_test_loop.cpp` is an example to show the complete process.
The source code is in [etm_test_loop.cpp](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/runtest/etm_test_loop.cpp).
The build script is in [Android.bp](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/runtest/Android.bp).
It builds an executable called `etm_test_loop`, which runs on device.

Step 1: Build `etm_test_loop` binary.

```sh
(host) <AOSP>$ . build/envsetup.sh
(host) <AOSP>$ lunch aosp_arm64-userdebug
(host) <AOSP>$ make etm_test_loop
```

Step 2: Run `etm_test_loop` on device, and collect ETM data for its running.

```sh
(host) <AOSP>$ adb push out/target/product/generic_arm64/system/bin/etm_test_loop /data/local/tmp
(host) <AOSP>$ adb root
(host) <AOSP>$ adb shell
(device) / # cd /data/local/tmp
(device) /data/local/tmp # chmod a+x etm_test_loop
(device) /data/local/tmp # simpleperf record -e cs-etm:u ./etm_test_loop
simpleperf I cmd_record.cpp:729] Recorded for 0.0370068 seconds. Start post processing.
simpleperf I cmd_record.cpp:799] Aux data traced: 1689136
(device) /data/local/tmp # simpleperf inject -i perf.data --output branch-list -o branch_list.data
simpleperf W dso.cpp:557] failed to read min virtual address of [vdso]: File not found
(device) /data/local/tmp # exit
(host) <AOSP>$ adb pull /data/local/tmp/branch_list.data
```

Step 3: Convert ETM data to AutoFDO data.

```sh
# Build simpleperf tool on host.
(host) <AOSP>$ make simpleperf_ndk
(host) <AOSP>$ simpleperf_ndk64 inject -i branch_list.data -o perf_inject_etm_test_loop.data --symdir out/target/product/generic_arm64/symbols/system/bin
simpleperf W cmd_inject.cpp:505] failed to build instr ranges for binary [vdso]: File not found
(host) <AOSP>$ cat perf_inject_etm_test_loop.data
13
1000-1010:1
1014-1050:1
...
112c->0:1
// /data/local/tmp/etm_test_loop

(host) <AOSP>$ create_llvm_prof -profile perf_inject_etm_test_loop.data -profiler text -binary out/target/product/generic_arm64/symbols/system/bin/etm_test_loop -out etm_test_loop.afdo -format binary
(host) <AOSP>$ ls -lh etm_test_loop.afdo
rw-r--r-- 1 user group 241 Aug 29 16:04 etm_test_loop.afdo
```

Step 4: Use AutoFDO data to build optimized binary.

```sh
(host) <AOSP>$ mkdir toolchain/pgo-profiles/sampling/
(host) <AOSP>$ cp etm_test_loop.afdo toolchain/pgo-profiles/sampling/
(host) <AOSP>$ vi toolchain/pgo-profiles/sampling/Android.bp
# edit Android.bp to add a fdo_profile module
# soong_namespace {}
#
# fdo_profile {
#    name: "etm_test_loop_afdo",
#    profile: ["etm_test_loop.afdo"],
# }
```

`soong_namespace` is added to support fdo_profile modules with the same name

In a product config mk file, update `PRODUCT_AFDO_PROFILES` with

```make
PRODUCT_AFDO_PROFILES += etm_test_loop://toolchain/pgo-profiles/sampling:etm_test_loop_afdo
```

```sh
(host) <AOSP>$ vi system/extras/simpleperf/runtest/Android.bp
# edit Android.bp to enable afdo for etm_test_loop.
# cc_binary {
#    name: "etm_test_loop",
#    srcs: ["etm_test_loop.cpp"],
#    afdo: true,
# }
(host) <AOSP>$ make etm_test_loop
```

If comparing the disassembly of `out/target/product/generic_arm64/symbols/system/bin/etm_test_loop`
before and after optimizing with AutoFDO data, we can see different preferences when branching.


## Collect ETM data with a daemon

Android also has a daemon collecting ETM data periodically. It only runs on userdebug and eng
devices. The source code is in https://android.googlesource.com/platform/system/extras/+/master/profcollectd/.

## Support ETM in the kernel

To let simpleperf use ETM function, we need to enable Coresight driver in the kernel, which lives in
`<linux_kernel>/drivers/hwtracing/coresight`.

The Coresight driver can be enabled by below kernel configs:

```config
	CONFIG_CORESIGHT=y
	CONFIG_CORESIGHT_LINK_AND_SINK_TMC=y
	CONFIG_CORESIGHT_SOURCE_ETM4X=y
```

On Kernel 5.10+, we recommend building Coresight driver as kernel modules. Because it works with
GKI kernel.

```config
	CONFIG_CORESIGHT=m
	CONFIG_CORESIGHT_LINK_AND_SINK_TMC=m
	CONFIG_CORESIGHT_SOURCE_ETM4X=m
```

Android common kernel 5.10+ should have all the Coresight patches needed to collect ETM data.
Android common kernel 5.4 misses two patches. But by adding patches in
https://android-review.googlesource.com/q/topic:test_etm_on_hikey960_5.4, we can collect ETM data
on hikey960 with 5.4 kernel.
For Android common kernel 4.14 and 4.19, we have backported all necessary Coresight patches.

Besides Coresight driver, we also need to add Coresight devices in device tree. An example is in
https://github.com/torvalds/linux/blob/master/arch/arm64/boot/dts/arm/juno-base.dtsi. There should
be a path flowing ETM data from ETM device through funnels, ETF and replicators, all the way to
ETR, which writes ETM data to system memory.

One optional flag in ETM device tree is "arm,coresight-loses-context-with-cpu". It saves ETM
registers when a CPU enters low power state. It may be needed to avoid
"coresight_disclaim_device_unlocked" warning when doing system wide collection.

One optional flag in ETR device tree is "arm,scatter-gather". Simpleperf requests 4M system memory
for ETR to store ETM data. Without IOMMU, the memory needs to be contiguous. If the kernel can't
fulfill the request, simpleperf will report out of memory error. Fortunately, we can use
"arm,scatter-gather" flag to let ETR run in scatter gather mode, which uses non-contiguous memory.


### A possible problem: trace_id mismatch

Each CPU has an ETM device, which has a unique trace_id assigned from the kernel.
The formula is: `trace_id = 0x10 + cpu * 2`, as in https://github.com/torvalds/linux/blob/master/include/linux/coresight-pmu.h#L37.
If the formula is modified by local patches, then simpleperf inject command can't parse ETM data
properly and is likely to give empty output.


## Enable ETM in the bootloader

Unless ARMv8.4 Self-hosted Trace extension is implemented, ETM is considered as an external debug
interface. It may be disabled by fuse (like JTAG). So we need to check if ETM is disabled, and
if bootloader provides a way to reenable it.

We can tell if ETM is disable by checking its TRCAUTHSTATUS register, which is exposed in sysfs,
like /sys/bus/coresight/devices/coresight-etm0/mgmt/trcauthstatus. To reenable ETM, we need to
enable non-Secure non-invasive debug on ARM CPU. The method depends on chip vendors(SOCs).


## Related docs

* [Arm Architecture Reference Manual Armv8, D3 AArch64 Self-hosted Trace](https://developer.arm.com/documentation/ddi0487/latest)
* [ARM ETM Architecture Specification](https://developer.arm.com/documentation/ihi0064/latest/)
* [ARM CoreSight Architecture Specification](https://developer.arm.com/documentation/ihi0029/latest)
* [CoreSight Components Technical Reference Manual](https://developer.arm.com/documentation/ddi0314/h/)
* [CoreSight Trace Memory Controller Technical Reference Manual](https://developer.arm.com/documentation/ddi0461/b/)
* [OpenCSD library for decoding ETM data](https://github.com/Linaro/OpenCSD)
* [AutoFDO tool for converting profile data](https://github.com/google/autofdo)
