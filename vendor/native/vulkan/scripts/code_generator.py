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

"""Generates vulkan framework directly from the vulkan registry (vk.xml).
"""

import api_generator
import driver_generator
import generator_common
import null_generator

if __name__ == '__main__':
  generator_common.parse_vulkan_registry()
  api_generator.gen_h()
  api_generator.gen_cpp()
  driver_generator.gen_h()
  driver_generator.gen_cpp()
  null_generator.gen_h()
  null_generator.gen_cpp()
