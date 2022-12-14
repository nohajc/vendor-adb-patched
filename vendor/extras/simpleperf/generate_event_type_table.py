#!/usr/bin/python
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


def gen_event_type_entry_str(event_type_name, event_type, event_config, description='',
                             limited_arch=''):
  """
  return string as below:
  EVENT_TYPE_TABLE_ENTRY(event_type_name, event_type, event_config, description, limited_arch)
  """
  return 'EVENT_TYPE_TABLE_ENTRY("%s", %s, %s, "%s", "%s")\n' % (
            event_type_name, event_type, event_config, description, limited_arch)

def gen_arm_event_type_entry_str(event_type_name, event_type, event_config, description):
  return gen_event_type_entry_str(event_type_name, event_type, event_config, description,
                                  "arm")


def gen_hardware_events():
  hardware_configs = ["cpu-cycles",
                      "instructions",
                      "cache-references",
                      "cache-misses",
                      "branch-instructions",
                      "branch-misses",
                      "bus-cycles",
                      "stalled-cycles-frontend",
                      "stalled-cycles-backend",
                      ]
  generated_str = ""
  for config in hardware_configs:
    event_type_name = config
    event_config = "PERF_COUNT_HW_" + config.replace('-', '_').upper()

    generated_str += gen_event_type_entry_str(
        event_type_name, "PERF_TYPE_HARDWARE", event_config)

  return generated_str


def gen_software_events():
  software_configs = ["cpu-clock",
                      "task-clock",
                      "page-faults",
                      "context-switches",
                      "cpu-migrations",
                      ["minor-faults", "PERF_COUNT_SW_PAGE_FAULTS_MIN"],
                      ["major-faults", "PERF_COUNT_SW_PAGE_FAULTS_MAJ"],
                      "alignment-faults",
                      "emulation-faults",
                      ]
  generated_str = ""
  for config in software_configs:
    if isinstance(config, list):
      event_type_name = config[0]
      event_config = config[1]
    else:
      event_type_name = config
      event_config = "PERF_COUNT_SW_" + config.replace('-', '_').upper()

    generated_str += gen_event_type_entry_str(
        event_type_name, "PERF_TYPE_SOFTWARE", event_config)

  return generated_str


def gen_hw_cache_events():
  hw_cache_types = [["L1-dcache", "PERF_COUNT_HW_CACHE_L1D"],
                    ["L1-icache", "PERF_COUNT_HW_CACHE_L1I"],
                    ["LLC", "PERF_COUNT_HW_CACHE_LL"],
                    ["dTLB", "PERF_COUNT_HW_CACHE_DTLB"],
                    ["iTLB", "PERF_COUNT_HW_CACHE_ITLB"],
                    ["branch", "PERF_COUNT_HW_CACHE_BPU"],
                    ["node", "PERF_COUNT_HW_CACHE_NODE"],
                    ]
  hw_cache_ops = [["loads", "load", "PERF_COUNT_HW_CACHE_OP_READ"],
                  ["stores", "store", "PERF_COUNT_HW_CACHE_OP_WRITE"],
                  ["prefetches", "prefetch",
                   "PERF_COUNT_HW_CACHE_OP_PREFETCH"],
                  ]
  hw_cache_op_results = [["accesses", "PERF_COUNT_HW_CACHE_RESULT_ACCESS"],
                         ["misses", "PERF_COUNT_HW_CACHE_RESULT_MISS"],
                         ]
  generated_str = ""
  for (type_name, type_config) in hw_cache_types:
    for (op_name_access, op_name_miss, op_config) in hw_cache_ops:
      for (result_name, result_config) in hw_cache_op_results:
        if result_name == "accesses":
          event_type_name = type_name + '-' + op_name_access
        else:
          event_type_name = type_name + '-' + \
              op_name_miss + '-' + result_name
        event_config = "((%s) | (%s << 8) | (%s << 16))" % (
            type_config, op_config, result_config)
        generated_str += gen_event_type_entry_str(
            event_type_name, "PERF_TYPE_HW_CACHE", event_config)

  return generated_str


def gen_arm_raw_events():
  raw_types = [
               # Refer to "Table D6-7 PMU common architectural and microarchitectural event numbers" in ARMv8 specification.
               [0x0000, "sw-incr", "Instruction architecturally executed, Condition code check pass, software increment"],
               [0x0001, "l1i-cache-refill", "Level 1 instruction cache refill"],
               [0x0002, "l1i-tlb-refill", "Attributable Level 1 instruction TLB refill"],
               [0x0003, "l1d-cache-refill", "Level 1 data cache refill"],
               [0x0004, "l1d-cache", "Level 1 data cache access"],
               [0x0005, "l1d-tlb-refill", "Attributable Level 1 data TLB refill"],
               [0x0006, "ld-retired", "Instruction architecturally executed, Condition code check pass, load"],
               [0x0007, "st-retired", "Instruction architecturally executed, Condition code check pass, store"],
               [0x0008, "inst-retired", "Instruction architecturally executed"],
               [0x0009, "exc-taken", "Exception taken"],
               [0x000A, "exc-return", "Instruction architecturally executed, Condition code check pass, exception return"],
               [0x000B, "cid-write-retired", "Instruction architecturally executed, Condition code check pass, write to CONTEXTIDR"],
               [0x000C, "pc-write-retired", "Instruction architecturally executed, Condition code check pass, software change of the PC"],
               [0x000D, "br-immed-retired", "Instruction architecturally executed, immediate branch"],
               [0x000E, "br-return-retired", "Instruction architecturally executed, Condition code check pass, procedure return"],
               [0x000F, "unaligned-ldst-retired", "Instruction architecturally executed, Condition code check pass, unaligned load or store"],
               [0x0010, "br-mis-pred", "Mispredicted or not predicted branch Speculatively executed"],
               [0x0011, "cpu-cycles", "Cycle"],
               [0x0012, "br-pred", "Predictable branch Speculatively executed"],
               [0x0013, "mem-access", "Data memory access"],
               [0x0014, "l1i-cache", "Attributable Level 1 instruction cache access"],
               [0x0015, "l1d-cache-wb", "Attributable Level 1 data cache write-back"],
               [0x0016, "l2d-cache", "Level 2 data cache access"],
               [0x0017, "l2d-cache-refill", "Level 2 data cache refill"],
               [0x0018, "l2d-cache-wb", "Attributable Level 2 data cache write-back"],
               [0x0019, "bus-access", "Bus access"],
               [0x001A, "memory-error", "Local memory error"],
               [0x001B, "inst-spec", "Operation Speculatively executed"],
               [0x001C, "ttbr-write-retired", "Instruction architecturally executed, Condition code check pass, write to TTBR"],
               [0x001D, "bus-cycles", "Bus cycle"],
               [0x001E, "chain", "For odd-numbered counters, increments the count by one for each overflow of the preceding even-numbered counter. For even-numbered counters, there is no increment."],
               [0x001F, "l1d-cache-allocate", "Attributable Level 1 data cache allocation without refill"],
               [0x0020, "l2d-cache-allocate", "Attributable Level 2 data cache allocation without refill"],
               [0x0021, "br-retired", "Instruction architecturally executed, branch"],
               [0x0022, "br-mis-pred-retired", "Instruction architecturally executed, mispredicted branch"],
               [0x0023, "stall-frontend", "No operation issued due to the frontend"],
               [0x0024, "stall-backend", "No operation issued due to backend"],
               [0x0025, "l1d-tlb", "Attributable Level 1 data or unified TLB access"],
               [0x0026, "l1i-tlb", "Attributable Level 1 instruction TLB access"],
               [0x0027, "l2i-cache", "Attributable Level 2 instruction cache access"],
               [0x0028, "l2i-cache-refill", "Attributable Level 2 instruction cache refill"],
               [0x0029, "l3d-cache-allocate", "Attributable Level 3 data or unified cache allocation without refill"],
               [0x002A, "l3d-cache-refill", "Attributable Level 3 data cache refill"],
               [0x002B, "l3d-cache", "Attributable Level 3 data cache access"],
               [0x002C, "l3d-cache-wb", "Attributable Level 3 data or unified cache write-back"],
               [0x002D, "l2d-tlb-refill", "Attributable Level 2 data or unified TLB refill"],
               [0x002E, "l2i-tlb-refill", "Attributable Level 2 instruction TLB refill"],
               [0x002F, "l2d-tlb", "Attributable Level 2 data or unified TLB access"],
               [0x0030, "l2i-tlb", "Attributable Level 2 instruction TLB access"],
               [0x0031, "remote-access", "Attributable access to another socket in a multi-socket system"],
               [0x0032, "ll-cache", "Attributable Last Level data cache access"],
               [0x0033, "ll-cache-miss", "Attributable Last level data or unified cache miss"],
               [0x0034, "dtlb-walk", "Attributable data or unified TLB access with at least one translation table walk"],
               [0x0035, "itlb-walk", "Attributable instruction TLB access with at least one translation table walk"],
               [0x0036, "ll-cache-rd", "Attributable Last Level cache memory read"],
               [0x0037, "ll-cache-miss-rd", "Attributable Last Level cache memory read miss"],
               [0x0038, "remote-access-rd", "Attributable memory read access to another socket in a multi-socket system"],
               [0x0039, "l1d-cache-lmiss-rd", "Level 1 data cache long-latency read miss"],
               [0x003A, "op-retired", "Micro-operation architecturally executed"],
               [0x003B, "op-spec", "Micro-operation Speculatively executed"],
               [0x003C, "stall", "No operation sent for execution"],
               [0x003D, "stall-slot-backend", "No operation sent for execution on a Slot due to the backend"],
               [0x003E, "stall-slot-frontend", "No operation send for execution on a Slot due to the frontend"],
               [0x003F, "stall-slot", "No operation sent for execution on a Slot"],
               [0x0040, "l1d-cache-rd", "Level 1 data cache read"],
               [0x4000, "sample-pop", "Sample Population"],
               [0x4001, "sample-feed", "Sample Taken"],
               [0x4002, "sample-filtrate", "Sample Taken and not removed by filtering"],
               [0x4003, "sample-collision", "Sample collided with previous sample"],
               [0x4004, "cnt-cycles", "Constant frequency cycles"],
               [0x4005, "stall-backend-mem", "Memory stall cycles"],
               [0x4006, "l1i-cache-lmiss", "Level 1 instruction cache long-latency miss"],
               [0x4009, "l2d-cache-lmiss-rd", "Level 2 data cache long-latency read miss"],
               [0x400A, "l2i-cache-lmiss", "Level 2 instruction cache long-latency miss"],
               [0x400B, "l3d-cache-lmiss-rd", "Level 3 data cache long-latency read miss"],
               [0x8002, "sve-inst-retired", "SVE Instructions architecturally executed"],
               [0x8006, "sve-inst-spec", "SVE Instructions speculatively executed"],

               # Refer to "Table K3.1 ARM recommendations for IMPLEMENTATION DEFINED event numbers" in ARMv8 specification.
               #[0x0040, "l1d-cache-rd", "Attributable Level 1 data cache access, read"],
               [0x0041, "l1d-cache-wr", "Attributable Level 1 data cache access, write"],
               [0x0042, "l1d-cache-refill-rd", "Attributable Level 1 data cache refill, read"],
               [0x0043, "l1d-cache-refill-wr", "Attributable Level 1 data cache refill, write"],
               [0x0044, "l1d-cache-refill-inner", "Attributable Level 1 data cache refill, inner"],
               [0x0045, "l1d-cache-refill-outer", "Attributable Level 1 data cache refill, outer"],
               [0x0046, "l1d-cache-wb-victim", "Attributable Level 1 data cache Write-Back, victim"],
               [0x0047, "l1d-cache-wb-clean", "Level 1 data cache Write-Back, cleaning and coherency"],
               [0x0048, "l1d-cache-inval", "Attributable Level 1 data cache invalidate"],
               # 0x0049-0x004B - Reserved
               [0x004C, "l1d-tlb-refill-rd", "Attributable Level 1 data TLB refill, read"],
               [0x004D, "l1d-tlb-refill-wr", "Attributable Level 1 data TLB refill, write"],
               [0x004E, "l1d-tlb-rd", "Attributable Level 1 data or unified TLB access, read"],
               [0x004F, "l1d-tlb-wr", "Attributable Level 1 data or unified TLB access, write"],
               [0x0050, "l2d-cache-rd", "Attributable Level 2 data cache access, read"],
               [0x0051, "l2d-cache-wr", "Attributable Level 2 data cache access, write"],
               [0x0052, "l2d-cache-refill-rd", "Attributable Level 2 data cache refill, read"],
               [0x0053, "l2d-cache-refill-wr", "Attributable Level 2 data cache refill, write"],
               # 0x0054-0x0055 - Reserved
               [0x0056, "l2d-cache-wb-victim", "Attributable Level 2 data cache Write-Back, victim"],
               [0x0057, "l2d-cache-wb-clean", "Level 2 data cache Write-Back, cleaning and coherency"],
               [0x0058, "l2d-cache-inval", "Attributable Level 2 data cache invalidate"],
               # 0x0059-0x005B - Reserved
               [0x005C, "l2d-tlb-refill-rd", "Attributable Level 2 data or unified TLB refill, read"],
               [0x005D, "l2d-tlb-refill-wr", "Attributable Level 2 data or unified TLB refill, write"],
               [0x005E, "l2d-tlb-rd", "Attributable Level 2 data or unified TLB access, read"],
               [0x005F, "l2d-tlb-wr", "Attributable Level 2 data or unified TLB access, write"],
               [0x0060, "bus-access-rd", "Bus access, read"],
               [0x0061, "bus-access-wr", "Bus access, write"],
               [0x0062, "bus-access-shared", "Bus access, Normal, Cacheable, Shareable"],
               [0x0063, "bus-access-not-shared", "Bus access, not Normal, Cacheable, Shareable"],
               [0x0064, "bus-access-normal", "Bus access, normal"],
               [0x0065, "bus-access-periph", "Bus access, peripheral"],
               [0x0066, "mem-access-rd", "Data memory access, read"],
               [0x0067, "mem-access-wr", "Data memory access, write"],
               [0x0068, "unaligned-ld-spec", "Unaligned access, read"],
               [0x0069, "unaligned-st-spec", "Unaligned access, write"],
               [0x006A, "unaligned-ldst-spec", "Unaligned access"],
               # 0x006B - Reserved
               [0x006C, "ldrex-spec", "Exclusive operation speculatively executed, LDREX or LDX"],
               [0x006D, "strex-pass-spec", "Exclusive operation speculatively executed, STREX or STX pass"],
               [0x006E, "strex-fail-spec", "Exclusive operation speculatively executed, STREX or STX fail"],
               [0x006F, "strex-spec", "Exclusive operation speculatively executed, STREX or STX"],
               [0x0070, "ld-spec", "Operation speculatively executed, load"],
               [0x0071, "st-spec", "Operation speculatively executed, store"],
               [0x0072, "ldst-spec", "Operation speculatively executed, load or store"],
               [0x0073, "dp-spec", "Operation speculatively executed, integer data processing"],
               [0x0074, "ase-spec", "Operation speculatively executed, Advanced SIMD instruction"],
               [0x0075, "vfp-spec", "Operation speculatively executed, floating-point instruction"],
               [0x0076, "pc-write-spec", "Operation speculatively executed, software change of the PC"],
               [0x0077, "crypto-spec", "Operation speculatively executed, Cryptographic instruction"],
               [0x0078, "br-immed-spec", "Branch speculatively executed, immediate branch"],
               [0x0079, "br-return-spec", "Branch speculatively executed, procedure return"],
               [0x007A, "br-indirect-spec", "Branch speculatively executed, indirect branch"],
               # 0x007B - Reserved
               [0x007C, "isb-spec", "Barrier speculatively executed, ISB"],
               [0x007D, "dsb-spec", "Barrier speculatively executed, DSB"],
               [0x007E, "dmb-spec", "Barrier speculatively executed, DMB"],
               # 0x007F-0x0080 - Reserved
               [0x0081, "exc-undef", "Exception taken, Other synchronous"],
               [0x0082, "exc-svc", "Exception taken, Supervisor Call"],
               [0x0083, "exc-pabort", "Exception taken, Instruction Abort"],
               [0x0084, "exc-dabort", "Exception taken, Data Abort and SError"],
               # 0x0085 - Reserved
               [0x0086, "exc-irq", "Exception taken, IRQ"],
               [0x0087, "exc-fiq", "Exception taken, FIQ"],
               [0x0088, "exc-smc", "Exception taken, Secure Monitor Call"],
               # 0x0089 - Reserved
               [0x008A, "exc-hvc", "Exception taken, Hypervisor Call"],
               [0x008B, "exc-trap-pabort", "Exception taken, Instruction Abort not Taken locallyb"],
               [0x008C, "exc-trap-dabort", "Exception taken, Data Abort or SError not Taken locallyb"],
               [0x008D, "exc-trap-other", "Exception taken, Other traps not Taken locallyb"],
               [0x008E, "exc-trap-irq", "Exception taken, IRQ not Taken locallyb"],
               [0x008F, "exc-trap-fiq", "Exception taken, FIQ not Taken locallyb"],
               [0x0090, "rc-ld-spec", "Release consistency operation speculatively executed, Load-Acquire"],
               [0x0091, "rc-st-spec", "Release consistency operation speculatively executed, Store-Release"],
               # 0x0092-0x009F - Reserved
               [0x00A0, "l3d-cache-rd", "Attributable Level 3 data or unified cache access, read"],
               [0x00A1, "l3d-cache-wr", "Attributable Level 3 data or unified cache access, write"],
               [0x00A2, "l3d-cache-refill-rd", "Attributable Level 3 data or unified cache refill, read"],
               [0x00A3, "l3d-cache-refill-wr", "Attributable Level 3 data or unified cache refill, write"],
               # 0x00A4-0x00A5 - Reserved
               [0x00A6, "l3d-cache-wb-victim", "Attributable Level 3 data or unified cache Write-Back, victim"],
               [0x00A7, "l3d-cache-wb-clean", "Attributable Level 3 data or unified cache Write-Back, cache clean"],
               [0x00A8, "l3d-cache-inval", "Attributable Level 3 data or unified cache access, invalidate"],
               ]
  generated_str = ""
  for item in raw_types:
    event_type = 'PERF_TYPE_RAW'
    event_type_name = "raw-" + item[1]
    event_config = '0x%x' % item[0]
    description = item[2]
    generated_str += gen_arm_event_type_entry_str(event_type_name, event_type, event_config,
                                              description)
  return generated_str


def gen_events():
  generated_str = "// This file is auto-generated by generate-event_table.py.\n\n"
  generated_str += gen_hardware_events() + '\n'
  generated_str += gen_software_events() + '\n'
  generated_str += gen_hw_cache_events() + '\n'
  generated_str += gen_arm_raw_events() + '\n'
  return generated_str

generated_str = gen_events()
fh = open('event_type_table.h', 'w')
fh.write(generated_str)
fh.close()
