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

"""Generates the null_driver_gen.h and null_driver_gen.cpp.
"""

import os
import generator_common as gencom

# Extensions implemented by the driver.
_DRIVER_EXTENSION_DICT = {
    'VK_ANDROID_native_buffer',
    'VK_EXT_debug_report',
    'VK_KHR_get_physical_device_properties2'
}


def _is_driver_function(cmd):
  """Returns true if the function is implemented by the driver.

  Args:
    cmd: Vulkan function name.
  """
  if cmd in gencom.extension_dict:
    return gencom.extension_dict[cmd] in _DRIVER_EXTENSION_DICT
  return True


def gen_h():
  """Generates the null_driver_gen.h file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'nulldrv', 'null_driver_gen.h')

  with open(genfile, 'w') as f:
    f.write(gencom.copyright_and_warning(2015))

    f.write("""\
#ifndef NULLDRV_NULL_DRIVER_H
#define NULLDRV_NULL_DRIVER_H 1

#include <vulkan/vk_android_native_buffer.h>
#include <vulkan/vulkan.h>

namespace null_driver {

PFN_vkVoidFunction GetGlobalProcAddr(const char* name);
PFN_vkVoidFunction GetInstanceProcAddr(const char* name);

// clang-format off\n""")

    for cmd in gencom.command_list:
      if _is_driver_function(cmd):
        param_list = [''.join(i) for i in gencom.param_dict[cmd]]
        f.write('VKAPI_ATTR ' + gencom.return_type_dict[cmd] + ' ' +
                gencom.base_name(cmd) + '(' + ', '.join(param_list) + ');\n')

    f.write("""\
// clang-format on

}  // namespace null_driver

#endif  // NULLDRV_NULL_DRIVER_H\n""")

    f.close()
  gencom.run_clang_format(genfile)


def gen_cpp():
  """Generates the null_driver_gen.cpp file.
  """
  genfile = os.path.join(os.path.dirname(__file__),
                         '..', 'nulldrv', 'null_driver_gen.cpp')

  with open(genfile, 'w') as f:
    f.write(gencom.copyright_and_warning(2015))

    f.write("""\
#include <algorithm>

#include "null_driver_gen.h"

using namespace null_driver;

namespace {

struct NameProc {
    const char* name;
    PFN_vkVoidFunction proc;
};

PFN_vkVoidFunction Lookup(const char* name,
                          const NameProc* begin,
                          const NameProc* end) {
    const auto& entry = std::lower_bound(
        begin, end, name,
        [](const NameProc& e, const char* n) { return strcmp(e.name, n) < 0; });
    if (entry == end || strcmp(entry->name, name) != 0)
        return nullptr;
    return entry->proc;
}

template <size_t N>
PFN_vkVoidFunction Lookup(const char* name, const NameProc (&procs)[N]) {
    return Lookup(name, procs, procs + N);
}

const NameProc kGlobalProcs[] = {
    // clang-format off\n""")

    sorted_command_list = sorted(gencom.command_list)
    for cmd in sorted_command_list:
      if (_is_driver_function(cmd) and
          gencom.get_dispatch_table_type(cmd) == 'Global'):
        f.write(gencom.indent(1) + '{\"' + cmd +
                '\", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_' +
                cmd + '>(' + gencom.base_name(cmd) + '))},\n')

    f.write("""\
    // clang-format on
};

const NameProc kInstanceProcs[] = {
    // clang-format off\n""")

    for cmd in sorted_command_list:
      if _is_driver_function(cmd):
        f.write(gencom.indent(1) + '{\"' + cmd +
                '\", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_' +
                cmd + '>(' + gencom.base_name(cmd) + '))},\n')

    f.write("""\
    // clang-format on
};

}  // namespace

namespace null_driver {

PFN_vkVoidFunction GetGlobalProcAddr(const char* name) {
    return Lookup(name, kGlobalProcs);
}

PFN_vkVoidFunction GetInstanceProcAddr(const char* name) {
    return Lookup(name, kInstanceProcs);
}

}  // namespace null_driver\n""")

    f.close()
  gencom.run_clang_format(genfile)
