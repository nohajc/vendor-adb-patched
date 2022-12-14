#!/usr/bin/env python3
#
# Copyright 2019 The Android Open Source Project
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

"""Generates the api_gen.h and api_gen.cpp.
"""

import os
import generator_common as gencom

# Functions intercepted at vulkan::api level.
_INTERCEPTED_COMMANDS = [
    'vkCreateDevice',
    'vkDestroyDevice',
    'vkDestroyInstance',
    'vkEnumerateDeviceExtensionProperties',
    'vkEnumerateDeviceLayerProperties',
]


def gen_h():
  """Generates the api_gen.h file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'libvulkan', 'api_gen.h')

  with open(genfile, 'w') as f:
    instance_dispatch_table_entries = []
    device_dispatch_table_entries = []

    for cmd in gencom.command_list:
      if cmd not in gencom.alias_dict:
        if gencom.is_instance_dispatch_table_entry(cmd):
          instance_dispatch_table_entries.append(
              'PFN_' + cmd + ' ' + gencom.base_name(cmd) + ';')
        elif gencom.is_device_dispatch_table_entry(cmd):
          device_dispatch_table_entries.append(
              'PFN_' + cmd + ' ' + gencom.base_name(cmd) + ';')

    f.write(gencom.copyright_and_warning(2016))

    f.write("""\
#ifndef LIBVULKAN_API_GEN_H
#define LIBVULKAN_API_GEN_H

#include <vulkan/vulkan.h>

#include <bitset>

#include "driver_gen.h"

namespace vulkan {
namespace api {

struct InstanceDispatchTable {
    // clang-format off\n""")

    for entry in instance_dispatch_table_entries:
      f.write(gencom.indent(1) + entry + '\n')

    f.write("""\
    // clang-format on
};

struct DeviceDispatchTable {
    // clang-format off\n""")

    for entry in device_dispatch_table_entries:
      f.write(gencom.indent(1) + entry + '\n')

    f.write("""\
    // clang-format on
};

bool InitDispatchTable(
    VkInstance instance,
    PFN_vkGetInstanceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions);
bool InitDispatchTable(
    VkDevice dev,
    PFN_vkGetDeviceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions);

}  // namespace api
}  // namespace vulkan

#endif  // LIBVULKAN_API_GEN_H\n""")

    f.close()
  gencom.run_clang_format(genfile)


def _define_extension_stub(cmd, f):
  """Emits a stub for an exported extension function.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  if (cmd in gencom.extension_dict and gencom.is_function_exported(cmd)):
    ext_name = gencom.extension_dict[cmd]
    ret = gencom.return_type_dict[cmd]
    params = gencom.param_dict[cmd]
    first_param = params[0][0] + params[0][1]
    tail_params = ', '.join([i[0][:-1] for i in params[1:]])

    f.write('VKAPI_ATTR ' + ret + ' disabled' + gencom.base_name(cmd) +
            '(' + first_param + ', ' + tail_params + ') {\n')

    f.write(gencom.indent(1) + 'driver::Logger(' + params[0][1] +
            ').Err(' + params[0][1] + ', \"' + ext_name +
            ' not enabled. Exported ' + cmd + ' not executed.\");\n')

    if gencom.return_type_dict[cmd] != 'void':
      f.write(gencom.indent(1) + 'return VK_SUCCESS;\n')

    f.write('}\n\n')


def _is_intercepted(cmd):
  """Returns true if a function is intercepted by vulkan::api.

  Args:
    cmd: Vulkan function name.
  """
  if gencom.is_function_supported(cmd):
    if gencom.is_globally_dispatched(cmd) or cmd in _INTERCEPTED_COMMANDS:
      return True
  return False


def _intercept_instance_proc_addr(f):
  """Emits code for vkGetInstanceProcAddr for function interception.

  Args:
    f: Output file handle.
  """
  f.write("""\
    // global functions
    if (instance == VK_NULL_HANDLE) {\n""")

  for cmd in gencom.command_list:
    # vkGetInstanceProcAddr(nullptr, "vkGetInstanceProcAddr") is effectively
    # globally dispatched
    if gencom.is_globally_dispatched(cmd) or cmd == 'vkGetInstanceProcAddr':
      f.write(gencom.indent(2) +
              'if (strcmp(pName, \"' + cmd +
              '\") == 0) return reinterpret_cast<PFN_vkVoidFunction>(' +
              gencom.base_name(cmd) + ');\n')

  f.write("""
        ALOGE("invalid vkGetInstanceProcAddr(VK_NULL_HANDLE, \\\"%s\\\") call", pName);
        return nullptr;
    }

    static const struct Hook {
        const char* name;
        PFN_vkVoidFunction proc;
    } hooks[] = {\n""")

  sorted_command_list = sorted(gencom.command_list)
  for cmd in sorted_command_list:
    if gencom.is_function_exported(cmd):
      if gencom.is_globally_dispatched(cmd):
        f.write(gencom.indent(2) + '{ \"' + cmd + '\", nullptr },\n')
      elif (_is_intercepted(cmd) or
            cmd == 'vkGetInstanceProcAddr' or
            gencom.is_device_dispatched(cmd)):
        f.write(gencom.indent(2) + '{ \"' + cmd +
                '\", reinterpret_cast<PFN_vkVoidFunction>(' +
                gencom.base_name(cmd) + ') },\n')

  f.write("""\
    };
    // clang-format on
    constexpr size_t count = sizeof(hooks) / sizeof(hooks[0]);
    auto hook = std::lower_bound(
        hooks, hooks + count, pName,
        [](const Hook& h, const char* n) { return strcmp(h.name, n) < 0; });
    if (hook < hooks + count && strcmp(hook->name, pName) == 0) {
        if (!hook->proc) {
            vulkan::driver::Logger(instance).Err(
                instance, "invalid vkGetInstanceProcAddr(%p, \\\"%s\\\") call",
                instance, pName);
        }
        return hook->proc;
    }
    // clang-format off\n\n""")


def _intercept_device_proc_addr(f):
  """Emits code for vkGetDeviceProcAddr for function interception.

  Args:
    f: Output file handle.
  """
  f.write("""\
    if (device == VK_NULL_HANDLE) {
        ALOGE("invalid vkGetDeviceProcAddr(VK_NULL_HANDLE, ...) call");
        return nullptr;
    }

    static const char* const known_non_device_names[] = {\n""")

  sorted_command_list = sorted(gencom.command_list)
  for cmd in sorted_command_list:
    if gencom.is_function_supported(cmd):
      if not gencom.is_device_dispatched(cmd):
        f.write(gencom.indent(2) + '\"' + cmd + '\",\n')

  f.write("""\
    };
    // clang-format on
    constexpr size_t count =
        sizeof(known_non_device_names) / sizeof(known_non_device_names[0]);
    if (!pName ||
        std::binary_search(
            known_non_device_names, known_non_device_names + count, pName,
            [](const char* a, const char* b) { return (strcmp(a, b) < 0); })) {
        vulkan::driver::Logger(device).Err(
            device, "invalid vkGetDeviceProcAddr(%p, \\\"%s\\\") call", device,
            (pName) ? pName : "(null)");
        return nullptr;
    }
    // clang-format off\n\n""")

  for cmd in gencom.command_list:
    if gencom.is_device_dispatched(cmd):
      if _is_intercepted(cmd) or cmd == 'vkGetDeviceProcAddr':
        f.write(gencom.indent(1) + 'if (strcmp(pName, "' + cmd +
                '") == 0) return reinterpret_cast<PFN_vkVoidFunction>(' +
                gencom.base_name(cmd) + ');\n')
  f.write('\n')


def _api_dispatch(cmd, f):
  """Emits code to dispatch a function.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  assert not _is_intercepted(cmd)

  f.write(gencom.indent(1))
  if gencom.return_type_dict[cmd] != 'void':
    f.write('return ')

  param_list = gencom.param_dict[cmd]
  handle = param_list[0][1]
  f.write('GetData(' + handle + ').dispatch.' + gencom.base_name(cmd) +
          '(' + ', '.join(i[1] for i in param_list) + ');\n')


def gen_cpp():
  """Generates the api_gen.cpp file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'libvulkan', 'api_gen.cpp')

  with open(genfile, 'w') as f:
    f.write(gencom.copyright_and_warning(2016))

    f.write("""\
#include <log/log.h>
#include <string.h>

#include <algorithm>

// to catch mismatches between vulkan.h and this file
#undef VK_NO_PROTOTYPES
#include "api.h"

namespace vulkan {
namespace api {

#define UNLIKELY(expr) __builtin_expect((expr), 0)

#define INIT_PROC(required, obj, proc)                                 \\
    do {                                                               \\
        data.dispatch.proc =                                           \\
            reinterpret_cast<PFN_vk##proc>(get_proc(obj, "vk" #proc)); \\
        if (UNLIKELY(required && !data.dispatch.proc)) {               \\
            ALOGE("missing " #obj " proc: vk" #proc);                  \\
            success = false;                                           \\
        }                                                              \\
    } while (0)

// Exported extension functions may be invoked even when their extensions
// are disabled.  Dispatch to stubs when that happens.
#define INIT_PROC_EXT(ext, required, obj, proc)  \\
    do {                                         \\
        if (extensions[driver::ProcHook::ext])   \\
            INIT_PROC(required, obj, proc);      \\
        else                                     \\
            data.dispatch.proc = disabled##proc; \\
    } while (0)

namespace {

// clang-format off\n\n""")

    for cmd in gencom.command_list:
      _define_extension_stub(cmd, f)

    f.write("""\
// clang-format on

}  // namespace

bool InitDispatchTable(
    VkInstance instance,
    PFN_vkGetInstanceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(instance);
    bool success = true;

    // clang-format off\n""")

    for cmd in gencom.command_list:
      if gencom.is_instance_dispatch_table_entry(cmd):
        gencom.init_proc(cmd, f)

    f.write("""\
    // clang-format on

    return success;
}

bool InitDispatchTable(
    VkDevice dev,
    PFN_vkGetDeviceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(dev);
    bool success = true;

    // clang-format off\n""")

    for cmd in gencom.command_list:
      if gencom.is_device_dispatch_table_entry(cmd):
        gencom.init_proc(cmd, f)

    f.write("""\
    // clang-format on

    return success;
}

// clang-format off

namespace {

// forward declarations needed by GetInstanceProcAddr and GetDeviceProcAddr
""")

    for cmd in gencom.command_list:
      if gencom.is_function_exported(cmd) and not _is_intercepted(cmd):
        param_list = [''.join(i) for i in gencom.param_dict[cmd]]
        f.write('VKAPI_ATTR ' + gencom.return_type_dict[cmd] + ' ' +
                gencom.base_name(cmd) + '(' + ', '.join(param_list) + ');\n')

    f.write('\n')
    for cmd in gencom.command_list:
      if gencom.is_function_exported(cmd) and not _is_intercepted(cmd):
        param_list = [''.join(i) for i in gencom.param_dict[cmd]]
        f.write('VKAPI_ATTR ' + gencom.return_type_dict[cmd] + ' ' +
                gencom.base_name(cmd) + '(' + ', '.join(param_list) + ') {\n')
        if cmd == 'vkGetInstanceProcAddr':
          _intercept_instance_proc_addr(f)
        elif cmd == 'vkGetDeviceProcAddr':
          _intercept_device_proc_addr(f)
        _api_dispatch(cmd, f)
        f.write('}\n\n')

    f.write("""
}  // anonymous namespace

// clang-format on

}  // namespace api
}  // namespace vulkan

// clang-format off\n\n""")

    for cmd in gencom.command_list:
      if gencom.is_function_exported(cmd):
        param_list = [''.join(i) for i in gencom.param_dict[cmd]]
        f.write('__attribute__((visibility("default")))\n')
        f.write('VKAPI_ATTR ' + gencom.return_type_dict[cmd] + ' ' +
                cmd + '(' + ', '.join(param_list) + ') {\n')
        f.write(gencom.indent(1))
        if gencom.return_type_dict[cmd] != 'void':
          f.write('return ')
        param_list = gencom.param_dict[cmd]
        f.write('vulkan::api::' + gencom.base_name(cmd) +
                '(' + ', '.join(i[1] for i in param_list) + ');\n}\n\n')

    f.write('// clang-format on\n')
    f.close()
  gencom.run_clang_format(genfile)
