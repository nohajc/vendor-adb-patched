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

"""Generates the driver_gen.h and driver_gen.cpp.
"""

import os
import generator_common as gencom

# Extensions intercepted at vulkan::driver level.
_INTERCEPTED_EXTENSIONS = [
    'VK_ANDROID_native_buffer',
    'VK_EXT_debug_report',
    'VK_EXT_hdr_metadata',
    'VK_EXT_swapchain_colorspace',
    'VK_GOOGLE_display_timing',
    'VK_KHR_android_surface',
    'VK_KHR_get_surface_capabilities2',
    'VK_KHR_incremental_present',
    'VK_KHR_shared_presentable_image',
    'VK_KHR_surface',
    'VK_KHR_swapchain',
]

# Extensions known to vulkan::driver level.
_KNOWN_EXTENSIONS = _INTERCEPTED_EXTENSIONS + [
    'VK_ANDROID_external_memory_android_hardware_buffer',
    'VK_KHR_bind_memory2',
    'VK_KHR_get_physical_device_properties2',
]

# Functions needed at vulkan::driver level.
_NEEDED_COMMANDS = [
    # Create functions of dispatchable objects
    'vkCreateDevice',
    'vkGetDeviceQueue',
    'vkGetDeviceQueue2',
    'vkAllocateCommandBuffers',

    # Destroy functions of dispatchable objects
    'vkDestroyInstance',
    'vkDestroyDevice',

    # Enumeration of extensions
    'vkEnumerateDeviceExtensionProperties',

    # We cache physical devices in loader.cpp
    'vkEnumeratePhysicalDevices',
    'vkEnumeratePhysicalDeviceGroups',

    'vkGetInstanceProcAddr',
    'vkGetDeviceProcAddr',

    'vkQueueSubmit',

    # VK_KHR_swapchain->VK_ANDROID_native_buffer translation
    'vkCreateImage',
    'vkDestroyImage',

    'vkGetPhysicalDeviceProperties',
    'vkGetPhysicalDeviceProperties2',
    'vkGetPhysicalDeviceProperties2KHR',

    # VK_KHR_swapchain v69 requirement
    'vkBindImageMemory2',
    'vkBindImageMemory2KHR',
]

# Functions intercepted at vulkan::driver level.
_INTERCEPTED_COMMANDS = [
    # Create functions of dispatchable objects
    'vkCreateInstance',
    'vkCreateDevice',
    'vkEnumeratePhysicalDevices',
    'vkEnumeratePhysicalDeviceGroups',
    'vkGetDeviceQueue',
    'vkGetDeviceQueue2',
    'vkAllocateCommandBuffers',

    # Destroy functions of dispatchable objects
    'vkDestroyInstance',
    'vkDestroyDevice',

    # Enumeration of extensions
    'vkEnumerateInstanceExtensionProperties',
    'vkEnumerateDeviceExtensionProperties',

    'vkGetInstanceProcAddr',
    'vkGetDeviceProcAddr',

    'vkQueueSubmit',

    # VK_KHR_swapchain v69 requirement
    'vkBindImageMemory2',
    'vkBindImageMemory2KHR',
]


def _is_driver_table_entry(cmd):
  """Returns true if a function is needed by vulkan::driver.

  Args:
    cmd: Vulkan function name.
  """
  if gencom.is_function_supported(cmd):
    if cmd in _NEEDED_COMMANDS:
      return True
    if cmd in gencom.extension_dict:
      if (gencom.extension_dict[cmd] == 'VK_ANDROID_native_buffer' or
          gencom.extension_dict[cmd] == 'VK_EXT_debug_report'):
        return True
  return False


def _is_instance_driver_table_entry(cmd):
  """Returns true if a instance-dispatched function is needed by vulkan::driver.

  Args:
    cmd: Vulkan function name.
  """
  return (_is_driver_table_entry(cmd) and
          gencom.is_instance_dispatched(cmd))


def _is_device_driver_table_entry(cmd):
  """Returns true if a device-dispatched function is needed by vulkan::driver.

  Args:
    cmd: Vulkan function name.
  """
  return (_is_driver_table_entry(cmd) and
          gencom.is_device_dispatched(cmd))


def gen_h():
  """Generates the driver_gen.h file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'libvulkan', 'driver_gen.h')

  with open(genfile, 'w') as f:
    f.write(gencom.copyright_and_warning(2016))

    f.write("""\
#ifndef LIBVULKAN_DRIVER_GEN_H
#define LIBVULKAN_DRIVER_GEN_H

#include <vulkan/vk_android_native_buffer.h>
#include <vulkan/vulkan.h>

#include <bitset>

namespace vulkan {
namespace driver {

struct ProcHook {
    enum Type {
        GLOBAL,
        INSTANCE,
        DEVICE,
    };
    enum Extension {\n""")

    for ext in _KNOWN_EXTENSIONS:
      f.write(gencom.indent(2) + gencom.base_ext_name(ext) + ',\n')

    f.write('\n')
    for version in gencom.version_code_list:
      f.write(gencom.indent(2) + 'EXTENSION_CORE_' + version + ',\n')

    # EXTENSION_COUNT must be the next enum after the highest API version.
    f.write("""\
        EXTENSION_COUNT,
        EXTENSION_UNKNOWN,
    };

    const char* name;
    Type type;
    Extension extension;

    PFN_vkVoidFunction proc;
    PFN_vkVoidFunction checked_proc;  // always nullptr for non-device hooks
};

struct InstanceDriverTable {
    // clang-format off\n""")

    for cmd in gencom.command_list:
      if _is_instance_driver_table_entry(cmd):
        f.write(gencom.indent(1) + 'PFN_' + cmd + ' ' +
                gencom.base_name(cmd) + ';\n')

    f.write("""\
    // clang-format on
};

struct DeviceDriverTable {
    // clang-format off\n""")

    for cmd in gencom.command_list:
      if _is_device_driver_table_entry(cmd):
        f.write(gencom.indent(1) + 'PFN_' + cmd + ' ' +
                gencom.base_name(cmd) + ';\n')

    f.write("""\
    // clang-format on
};

const ProcHook* GetProcHook(const char* name);
ProcHook::Extension GetProcHookExtension(const char* name);

bool InitDriverTable(VkInstance instance,
                     PFN_vkGetInstanceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions);
bool InitDriverTable(VkDevice dev,
                     PFN_vkGetDeviceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions);

}  // namespace driver
}  // namespace vulkan

#endif  // LIBVULKAN_DRIVER_TABLE_H\n""")

    f.close()
  gencom.run_clang_format(genfile)


def _is_intercepted(cmd):
  """Returns true if a function is intercepted by vulkan::driver.

  Args:
    cmd: Vulkan function name.
  """
  if gencom.is_function_supported(cmd):
    if cmd in _INTERCEPTED_COMMANDS:
      return True

    if cmd in gencom.extension_dict:
      return gencom.extension_dict[cmd] in _INTERCEPTED_EXTENSIONS
  return False


def _get_proc_hook_enum(cmd):
  """Returns the ProcHook enumeration for the corresponding core function.

  Args:
    cmd: Vulkan function name.
  """
  assert cmd in gencom.version_dict
  for version in gencom.version_code_list:
    if gencom.version_dict[cmd] == 'VK_VERSION_' + version:
      return 'ProcHook::EXTENSION_CORE_' + version


def _need_proc_hook_stub(cmd):
  """Returns true if a function needs a ProcHook stub.

  Args:
    cmd: Vulkan function name.
  """
  if _is_intercepted(cmd) and gencom.is_device_dispatched(cmd):
    if cmd in gencom.extension_dict:
      if not gencom.is_extension_internal(gencom.extension_dict[cmd]):
        return True
    elif gencom.version_dict[cmd] != 'VK_VERSION_1_0':
      return True
  return False


def _define_proc_hook_stub(cmd, f):
  """Emits a stub for ProcHook::checked_proc.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  if _need_proc_hook_stub(cmd):
    return_type = gencom.return_type_dict[cmd]

    ext_name = ''
    ext_hook = ''
    if cmd in gencom.extension_dict:
      ext_name = gencom.extension_dict[cmd]
      ext_hook = 'ProcHook::' + gencom.base_ext_name(ext_name)
    else:
      ext_name = gencom.version_dict[cmd]
      ext_hook = _get_proc_hook_enum(cmd)

    handle = gencom.param_dict[cmd][0][1]
    param_types = ', '.join([''.join(i) for i in gencom.param_dict[cmd]])
    param_names = ', '.join([''.join(i[1]) for i in gencom.param_dict[cmd]])

    f.write('VKAPI_ATTR ' + return_type + ' checked' + gencom.base_name(cmd) +
            '(' + param_types + ') {\n')
    f.write(gencom.indent(1) + 'if (GetData(' + handle + ').hook_extensions[' +
            ext_hook + ']) {\n')

    f.write(gencom.indent(2))
    if gencom.return_type_dict[cmd] != 'void':
      f.write('return ')
    f.write(gencom.base_name(cmd) + '(' + param_names + ');\n')

    f.write(gencom.indent(1) + '} else {\n')
    f.write(gencom.indent(2) + 'Logger(' + handle + ').Err(' + handle + ', \"' +
            ext_name + ' not enabled. ' + cmd + ' not executed.\");\n')
    if gencom.return_type_dict[cmd] != 'void':
      f.write(gencom.indent(2) + 'return VK_SUCCESS;\n')
    f.write(gencom.indent(1) + '}\n}\n\n')


def _define_global_proc_hook(cmd, f):
  """Emits definition of a global ProcHook.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  assert cmd not in gencom.extension_dict

  f.write(gencom.indent(1) + '{\n')
  f.write(gencom.indent(2) + '\"' + cmd + '\",\n')
  f.write(gencom.indent(2) + 'ProcHook::GLOBAL,\n')
  f.write(gencom.indent(2) + _get_proc_hook_enum(cmd) + ',\n')
  f.write(gencom.indent(2) + 'reinterpret_cast<PFN_vkVoidFunction>(' +
          gencom.base_name(cmd) + '),\n')
  f.write(gencom.indent(2) + 'nullptr,\n')
  f.write(gencom.indent(1) + '},\n')


def _define_instance_proc_hook(cmd, f):
  """Emits definition of a instance ProcHook.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  f.write(gencom.indent(1) + '{\n')
  f.write(gencom.indent(2) + '\"' + cmd + '\",\n')
  f.write(gencom.indent(2) + 'ProcHook::INSTANCE,\n')

  if cmd in gencom.extension_dict:
    ext_name = gencom.extension_dict[cmd]
    f.write(gencom.indent(2) + 'ProcHook::' +
            gencom.base_ext_name(ext_name) + ',\n')

    if gencom.is_extension_internal(ext_name):
      f.write("""\
        nullptr,
        nullptr,\n""")
    else:
      f.write("""\
        reinterpret_cast<PFN_vkVoidFunction>(""" + gencom.base_name(cmd) + """),
        nullptr,\n""")
  else:
    f.write(gencom.indent(2) + _get_proc_hook_enum(cmd) + ',\n')
    f.write("""\
        reinterpret_cast<PFN_vkVoidFunction>(""" + gencom.base_name(cmd) + """),
        nullptr,\n""")

  f.write(gencom.indent(1) + '},\n')


def _define_device_proc_hook(cmd, f):
  """Emits definition of a device ProcHook.

  Args:
    cmd: Vulkan function name.
    f: Output file handle.
  """
  f.write(gencom.indent(1) + '{\n')
  f.write(gencom.indent(2) + '\"' + cmd + '\",\n')
  f.write(gencom.indent(2) + 'ProcHook::DEVICE,\n')

  if (cmd in gencom.extension_dict or
      gencom.version_dict[cmd] != 'VK_VERSION_1_0'):
    ext_name = ''
    ext_hook = ''
    if cmd in gencom.extension_dict:
      ext_name = gencom.extension_dict[cmd]
      ext_hook = 'ProcHook::' + gencom.base_ext_name(ext_name)
    else:
      ext_name = gencom.version_dict[cmd]
      ext_hook = _get_proc_hook_enum(cmd)
    f.write(gencom.indent(2) + ext_hook + ',\n')

    if gencom.is_extension_internal(ext_name):
      f.write("""\
        nullptr,
        nullptr,\n""")
    else:
      f.write("""\
        reinterpret_cast<PFN_vkVoidFunction>(""" + gencom.base_name(cmd) + """),
        reinterpret_cast<PFN_vkVoidFunction>(checked""" +
              gencom.base_name(cmd) + '),\n')

  else:
    f.write(gencom.indent(2) + _get_proc_hook_enum(cmd) + ',\n')
    f.write("""\
        reinterpret_cast<PFN_vkVoidFunction>(""" + gencom.base_name(cmd) + """),
        nullptr,\n""")

  f.write(gencom.indent(1) + '},\n')


def gen_cpp():
  """Generates the driver_gen.cpp file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'libvulkan', 'driver_gen.cpp')

  with open(genfile, 'w') as f:
    f.write(gencom.copyright_and_warning(2016))
    f.write("""\
#include <log/log.h>
#include <string.h>

#include <algorithm>

#include "driver.h"

namespace vulkan {
namespace driver {

namespace {

// clang-format off\n\n""")

    for cmd in gencom.command_list:
      _define_proc_hook_stub(cmd, f)

    f.write("""\
// clang-format on

const ProcHook g_proc_hooks[] = {
    // clang-format off\n""")

    sorted_command_list = sorted(gencom.command_list)
    for cmd in sorted_command_list:
      if _is_intercepted(cmd):
        if gencom.is_globally_dispatched(cmd):
          _define_global_proc_hook(cmd, f)
        elif gencom.is_instance_dispatched(cmd):
          _define_instance_proc_hook(cmd, f)
        elif gencom.is_device_dispatched(cmd):
          _define_device_proc_hook(cmd, f)

    f.write("""\
    // clang-format on
};

}  // namespace

const ProcHook* GetProcHook(const char* name) {
    const auto& begin = g_proc_hooks;
    const auto& end =
        g_proc_hooks + sizeof(g_proc_hooks) / sizeof(g_proc_hooks[0]);
    const auto hook = std::lower_bound(
        begin, end, name,
        [](const ProcHook& e, const char* n) { return strcmp(e.name, n) < 0; });
    return (hook < end && strcmp(hook->name, name) == 0) ? hook : nullptr;
}

ProcHook::Extension GetProcHookExtension(const char* name) {
    // clang-format off\n""")

    for ext in _KNOWN_EXTENSIONS:
      f.write(gencom.indent(1) + 'if (strcmp(name, \"' + ext +
              '\") == 0) return ProcHook::' + gencom.base_ext_name(ext) + ';\n')

    f.write("""\
    // clang-format on
    return ProcHook::EXTENSION_UNKNOWN;
}

#define UNLIKELY(expr) __builtin_expect((expr), 0)

#define INIT_PROC(required, obj, proc)                                 \\
    do {                                                               \\
        data.driver.proc =                                             \\
            reinterpret_cast<PFN_vk##proc>(get_proc(obj, "vk" #proc)); \\
        if (UNLIKELY(required && !data.driver.proc)) {                 \\
            ALOGE("missing " #obj " proc: vk" #proc);                  \\
            success = false;                                           \\
        }                                                              \\
    } while (0)

#define INIT_PROC_EXT(ext, required, obj, proc) \\
    do {                                        \\
        if (extensions[ProcHook::ext])          \\
            INIT_PROC(required, obj, proc);     \\
    } while (0)

bool InitDriverTable(VkInstance instance,
                     PFN_vkGetInstanceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(instance);
    bool success = true;

    // clang-format off\n""")

    for cmd in gencom.command_list:
      if _is_instance_driver_table_entry(cmd):
        gencom.init_proc(cmd, f)

    f.write("""\
    // clang-format on

    return success;
}

bool InitDriverTable(VkDevice dev,
                     PFN_vkGetDeviceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(dev);
    bool success = true;

    // clang-format off\n""")

    for cmd in gencom.command_list:
      if _is_device_driver_table_entry(cmd):
        gencom.init_proc(cmd, f)

    f.write("""\
    // clang-format on

    return success;
}

}  // namespace driver
}  // namespace vulkan\n""")

    f.close()
  gencom.run_clang_format(genfile)
