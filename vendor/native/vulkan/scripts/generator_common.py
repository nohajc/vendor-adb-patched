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

"""Provide the utilities for framework generation.
"""

import os
import subprocess
import xml.etree.ElementTree as element_tree

# Extensions unsupported on Android.
_BLOCKED_EXTENSIONS = [
    'VK_EXT_acquire_xlib_display',
    'VK_EXT_direct_mode_display',
    'VK_EXT_directfb_surface',
    'VK_EXT_display_control',
    'VK_EXT_display_surface_counter',
    'VK_EXT_full_screen_exclusive',
    'VK_EXT_headless_surface',
    'VK_EXT_metal_surface',
    'VK_FUCHSIA_imagepipe_surface',
    'VK_GGP_stream_descriptor_surface',
    'VK_HUAWEI_subpass_shading',
    'VK_KHR_display',
    'VK_KHR_display_swapchain',
    'VK_KHR_external_fence_win32',
    'VK_KHR_external_memory_win32',
    'VK_KHR_external_semaphore_win32',
    'VK_KHR_mir_surface',
    'VK_KHR_wayland_surface',
    'VK_KHR_win32_keyed_mutex',
    'VK_KHR_win32_surface',
    'VK_KHR_xcb_surface',
    'VK_KHR_xlib_surface',
    'VK_MVK_ios_surface',
    'VK_MVK_macos_surface',
    'VK_NN_vi_surface',
    'VK_NV_acquire_winrt_display',
    'VK_NV_cooperative_matrix',
    'VK_NV_coverage_reduction_mode',
    'VK_NV_external_memory_win32',
    'VK_NV_win32_keyed_mutex',
    'VK_NVX_image_view_handle',
    'VK_QNX_screen_surface',
]

# Extensions having functions exported by the loader.
_EXPORTED_EXTENSIONS = [
    'VK_ANDROID_external_memory_android_hardware_buffer',
    'VK_KHR_android_surface',
    'VK_KHR_surface',
    'VK_KHR_swapchain',
]

# Functions optional on Android even if extension is advertised.
_OPTIONAL_COMMANDS = [
    'vkGetSwapchainGrallocUsageANDROID',
    'vkGetSwapchainGrallocUsage2ANDROID',
    'vkGetSwapchainGrallocUsage3ANDROID',
]

# Dict for mapping dispatch table to a type.
_DISPATCH_TYPE_DICT = {
    'VkInstance ': 'Instance',
    'VkPhysicalDevice ': 'Instance',
    'VkDevice ': 'Device',
    'VkQueue ': 'Device',
    'VkCommandBuffer ': 'Device'
}

# Dict for mapping a function to its alias.
alias_dict = {}

# List of all the Vulkan functions.
command_list = []

# Dict for mapping a function to an extension.
extension_dict = {}

# Dict for mapping a function to all its parameters.
param_dict = {}

# Dict for mapping a function to its return type.
return_type_dict = {}

# List of the sorted Vulkan version codes. e.g. '1_0', '1_1'.
version_code_list = []

# Dict for mapping a function to the core Vulkan API version.
version_dict = {}

# Dict for mapping a promoted instance extension to the core Vulkan API version.
promoted_inst_ext_dict = {}


def indent(num):
  """Returns the requested indents.

  Args:
    num: Number of the 4-space indents.
  """
  return '    ' * num


def copyright_and_warning(year):
  """Returns the standard copyright and warning codes.

  Args:
    year: An integer year for the copyright.
  """
  return """\
/*
 * Copyright """ + str(year) + """ The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// WARNING: This file is generated. See ../README.md for instructions.

"""


def run_clang_format(args):
  """Run clang format on the file.

  Args:
    args: The file to be formatted.
  """
  clang_call = ['clang-format', '--style', 'file', '-i', args]
  subprocess.check_call(clang_call)


def is_extension_internal(ext):
  """Returns true if an extension is internal to the loader and drivers.

  The loader should not enumerate this extension.

  Args:
    ext: Vulkan extension name.
  """
  return ext == 'VK_ANDROID_native_buffer'


def base_name(cmd):
  """Returns a function name without the 'vk' prefix.

  Args:
    cmd: Vulkan function name.
  """
  return cmd[2:]


def base_ext_name(ext):
  """Returns an extension name without the 'VK_' prefix.

  Args:
    ext: Vulkan extension name.
  """
  return ext[3:]


def version_code(version):
  """Returns the version code from a version string.

  Args:
    version: Vulkan version string.
  """
  return version[11:]


def version_2_api_version(version):
  """Returns the api version from a version string.

  Args:
    version: Vulkan version string.
  """
  return 'VK_API' + version[2:]


def is_function_supported(cmd):
  """Returns true if a function is core or from a supportable extension.

  Args:
    cmd: Vulkan function name.
  """
  if cmd not in extension_dict:
    return True
  else:
    if extension_dict[cmd] not in _BLOCKED_EXTENSIONS:
      return True
  return False


def get_dispatch_table_type(cmd):
  """Returns the dispatch table type for a function.

  Args:
    cmd: Vulkan function name.
  """
  if cmd not in param_dict:
    return None

  if param_dict[cmd]:
    return _DISPATCH_TYPE_DICT.get(param_dict[cmd][0][0], 'Global')
  return 'Global'


def is_globally_dispatched(cmd):
  """Returns true if the function is global, which is not dispatched.

  Only global functions and functions handled in the loader top without calling
  into lower layers are not dispatched.

  Args:
    cmd: Vulkan function name.
  """
  return is_function_supported(cmd) and get_dispatch_table_type(cmd) == 'Global'


def is_instance_dispatched(cmd):
  """Returns true for functions that can have instance-specific dispatch.

  Args:
    cmd: Vulkan function name.
  """
  return (is_function_supported(cmd) and
          get_dispatch_table_type(cmd) == 'Instance')


def is_device_dispatched(cmd):
  """Returns true for functions that can have device-specific dispatch.

  Args:
    cmd: Vulkan function name.
  """
  return is_function_supported(cmd) and get_dispatch_table_type(cmd) == 'Device'


def is_extension_exported(ext):
  """Returns true if an extension has functions exported by the loader.

  E.g. applications can directly link to an extension function.

  Args:
    ext: Vulkan extension name.
  """
  return ext in _EXPORTED_EXTENSIONS


def is_function_exported(cmd):
  """Returns true if a function is exported from the Android Vulkan library.

  Functions in the core API and in loader extensions are exported.

  Args:
    cmd: Vulkan function name.
  """
  if is_function_supported(cmd):
    if cmd in extension_dict:
      return is_extension_exported(extension_dict[cmd])
    return True
  return False


def is_instance_dispatch_table_entry(cmd):
  """Returns true if a function is exported and instance-dispatched.

  Args:
    cmd: Vulkan function name.
  """
  if cmd == 'vkEnumerateDeviceLayerProperties':
    # deprecated, unused internally - @dbd33bc
    return False
  return is_function_exported(cmd) and is_instance_dispatched(cmd)


def is_device_dispatch_table_entry(cmd):
  """Returns true if a function is exported and device-dispatched.

  Args:
    cmd: Vulkan function name.
  """
  return is_function_exported(cmd) and is_device_dispatched(cmd)


def init_proc(name, f):
  """Emits code to invoke INIT_PROC or INIT_PROC_EXT.

  Args:
    name: Vulkan function name.
    f: Output file handle.
  """
  f.write(indent(1))
  if name in extension_dict:
    f.write('INIT_PROC_EXT(' + base_ext_name(extension_dict[name]) + ', ')
  else:
    f.write('INIT_PROC(')

  if name in _OPTIONAL_COMMANDS:
    f.write('false, ')
  elif version_dict[name] == 'VK_VERSION_1_0':
    f.write('true, ')
  else:
    f.write('false, ')

  if is_instance_dispatched(name):
    f.write('instance, ')
  else:
    f.write('dev, ')

  f.write(base_name(name) + ');\n')


def parse_vulkan_registry():
  """Parses Vulkan registry into the below global variables.

  alias_dict
  command_list
  extension_dict
  param_dict
  return_type_dict
  version_code_list
  version_dict
  promoted_inst_ext_dict
  """
  registry = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..',
                          'external', 'vulkan-headers', 'registry', 'vk.xml')
  tree = element_tree.parse(registry)
  root = tree.getroot()
  for commands in root.iter('commands'):
    for command in commands:
      if command.tag == 'command':
        parameter_list = []
        protoset = False
        cmd_name = ''
        cmd_type = ''
        if command.get('alias') is not None:
          alias = command.get('alias')
          cmd_name = command.get('name')
          alias_dict[cmd_name] = alias
          command_list.append(cmd_name)
          param_dict[cmd_name] = param_dict[alias].copy()
          return_type_dict[cmd_name] = return_type_dict[alias]
        for params in command:
          if params.tag == 'param':
            param_type = ''
            if params.text is not None and params.text.strip():
              param_type = params.text.strip() + ' '
            type_val = params.find('type')
            param_type = param_type + type_val.text
            if type_val.tail is not None:
              param_type += type_val.tail.strip() + ' '
            pname = params.find('name')
            param_name = pname.text
            if pname.tail is not None and pname.tail.strip():
              parameter_list.append(
                  (param_type, param_name, pname.tail.strip()))
            else:
              parameter_list.append((param_type, param_name))
          if params.tag == 'proto':
            for c in params:
              if c.tag == 'type':
                cmd_type = c.text
              if c.tag == 'name':
                cmd_name = c.text
                protoset = True
                command_list.append(cmd_name)
                return_type_dict[cmd_name] = cmd_type
        if protoset:
          param_dict[cmd_name] = parameter_list.copy()

  for exts in root.iter('extensions'):
    for extension in exts:
      apiversion = 'VK_VERSION_1_0'
      if extension.tag == 'extension':
        extname = extension.get('name')
        if (extension.get('type') == 'instance' and
            extension.get('promotedto') is not None):
          promoted_inst_ext_dict[extname] = \
              version_2_api_version(extension.get('promotedto'))
        for req in extension:
          if req.get('feature') is not None:
            apiversion = req.get('feature')
          for commands in req:
            if commands.tag == 'command':
              cmd_name = commands.get('name')
              if cmd_name not in extension_dict:
                extension_dict[cmd_name] = extname
                version_dict[cmd_name] = apiversion

  for feature in root.iter('feature'):
    apiversion = feature.get('name')
    for req in feature:
      for command in req:
        if command.tag == 'command':
          cmd_name = command.get('name')
          if cmd_name in command_list:
            version_dict[cmd_name] = apiversion

  version_code_set = set()
  for version in version_dict.values():
    version_code_set.add(version_code(version))
  for code in sorted(version_code_set):
    version_code_list.append(code)
