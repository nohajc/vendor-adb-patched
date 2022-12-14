///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2015-2016 The Khronos Group Inc.
// Copyright (c) 2015-2016 Valve Corporation
// Copyright (c) 2015-2016 LunarG, Inc.
// Copyright (c) 2015-2016 Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
///////////////////////////////////////////////////////////////////////////////

#ifndef VK_PROTOTYPES
#define VK_PROTOTYPES
#endif

#include "vkjson.h"

#include <algorithm>
#include <utility>

namespace {

bool EnumerateExtensions(const char* layer_name,
                         std::vector<VkExtensionProperties>* extensions) {
  VkResult result;
  uint32_t count = 0;
  result = vkEnumerateInstanceExtensionProperties(layer_name, &count, nullptr);
  if (result != VK_SUCCESS)
    return false;
  extensions->resize(count);
  result = vkEnumerateInstanceExtensionProperties(layer_name, &count,
                                                  extensions->data());
  if (result != VK_SUCCESS)
    return false;
  return true;
}

bool HasExtension(const char* extension_name,
                  const std::vector<VkExtensionProperties>& extensions) {
  return std::find_if(extensions.cbegin(), extensions.cend(),
                      [extension_name](const VkExtensionProperties& extension) {
                        return strcmp(extension.extensionName,
                                      extension_name) == 0;
                      }) != extensions.cend();
}
}  // anonymous namespace

VkJsonDevice VkJsonGetDevice(VkPhysicalDevice physical_device) {
  VkJsonDevice device;

  uint32_t extension_count = 0;
  vkEnumerateDeviceExtensionProperties(physical_device, nullptr,
                                       &extension_count, nullptr);
  if (extension_count > 0) {
    device.extensions.resize(extension_count);
    vkEnumerateDeviceExtensionProperties(
        physical_device, nullptr, &extension_count, device.extensions.data());
  }

  uint32_t layer_count = 0;
  vkEnumerateDeviceLayerProperties(physical_device, &layer_count, nullptr);
  if (layer_count > 0) {
    device.layers.resize(layer_count);
    vkEnumerateDeviceLayerProperties(physical_device, &layer_count,
                                     device.layers.data());
  }

  VkPhysicalDeviceProperties2 properties = {
      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
      nullptr,
      {},
  };
  if (HasExtension("VK_KHR_driver_properties", device.extensions)) {
    device.ext_driver_properties.reported = true;
    device.ext_driver_properties.driver_properties_khr.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES_KHR;
    device.ext_driver_properties.driver_properties_khr.pNext = properties.pNext;
    properties.pNext = &device.ext_driver_properties.driver_properties_khr;
  }
  vkGetPhysicalDeviceProperties2(physical_device, &properties);
  device.properties = properties.properties;

  VkPhysicalDeviceFeatures2 features = {
      VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
      nullptr,
      {},
  };
  if (HasExtension("VK_KHR_variable_pointers", device.extensions)) {
    device.ext_variable_pointer_features.reported = true;
    device.ext_variable_pointer_features.variable_pointer_features_khr.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VARIABLE_POINTER_FEATURES_KHR;
    device.ext_variable_pointer_features.variable_pointer_features_khr.pNext =
        features.pNext;
    features.pNext =
        &device.ext_variable_pointer_features.variable_pointer_features_khr;
  }
  if (HasExtension("VK_KHR_shader_float16_int8", device.extensions)) {
    device.ext_shader_float16_int8_features.reported = true;
    device.ext_shader_float16_int8_features.shader_float16_int8_features_khr
        .sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT16_INT8_FEATURES_KHR;
    device.ext_shader_float16_int8_features.shader_float16_int8_features_khr
        .pNext = features.pNext;
    features.pNext = &device.ext_shader_float16_int8_features
                          .shader_float16_int8_features_khr;
  }
  vkGetPhysicalDeviceFeatures2(physical_device, &features);
  device.features = features.features;

  vkGetPhysicalDeviceMemoryProperties(physical_device, &device.memory);

  uint32_t queue_family_count = 0;
  vkGetPhysicalDeviceQueueFamilyProperties(physical_device, &queue_family_count,
                                           nullptr);
  if (queue_family_count > 0) {
    device.queues.resize(queue_family_count);
    vkGetPhysicalDeviceQueueFamilyProperties(
        physical_device, &queue_family_count, device.queues.data());
  }

  VkFormatProperties format_properties = {};
  for (VkFormat format = VK_FORMAT_R4G4_UNORM_PACK8;
       // TODO(http://b/171403054): avoid hard-coding last value in the
       // contiguous range
       format <= VK_FORMAT_ASTC_12x12_SRGB_BLOCK;
       format = static_cast<VkFormat>(format + 1)) {
    vkGetPhysicalDeviceFormatProperties(physical_device, format,
                                        &format_properties);
    if (format_properties.linearTilingFeatures ||
        format_properties.optimalTilingFeatures ||
        format_properties.bufferFeatures) {
      device.formats.insert(std::make_pair(format, format_properties));
    }
  }

  if (device.properties.apiVersion >= VK_API_VERSION_1_1) {
    for (VkFormat format = VK_FORMAT_G8B8G8R8_422_UNORM;
         // TODO(http://b/171403054): avoid hard-coding last value in the
         // contiguous range
         format <= VK_FORMAT_G16_B16_R16_3PLANE_444_UNORM;
         format = static_cast<VkFormat>(format + 1)) {
      vkGetPhysicalDeviceFormatProperties(physical_device, format,
                                          &format_properties);
      if (format_properties.linearTilingFeatures ||
          format_properties.optimalTilingFeatures ||
          format_properties.bufferFeatures) {
        device.formats.insert(std::make_pair(format, format_properties));
      }
    }

    VkPhysicalDeviceProperties2 properties2 = {
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
        nullptr,
        {},
    };

    device.subgroup_properties.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_PROPERTIES;
    device.subgroup_properties.pNext = properties2.pNext;
    properties2.pNext = &device.subgroup_properties;

    device.point_clipping_properties.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_POINT_CLIPPING_PROPERTIES;
    device.point_clipping_properties.pNext = properties2.pNext;
    properties2.pNext = &device.point_clipping_properties;

    device.multiview_properties.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_PROPERTIES;
    device.multiview_properties.pNext = properties2.pNext;
    properties2.pNext = &device.multiview_properties;

    device.id_properties.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
    device.id_properties.pNext = properties2.pNext;
    properties2.pNext = &device.id_properties;

    device.maintenance3_properties.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_3_PROPERTIES;
    device.maintenance3_properties.pNext = properties2.pNext;
    properties2.pNext = &device.maintenance3_properties;

    vkGetPhysicalDeviceProperties2(physical_device, &properties2);

    VkPhysicalDeviceFeatures2 features2 = {
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
        nullptr,
        {},
    };

    device.bit16_storage_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_16BIT_STORAGE_FEATURES;
    device.bit16_storage_features.pNext = features2.pNext;
    features2.pNext = &device.bit16_storage_features;

    device.multiview_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_FEATURES;
    device.multiview_features.pNext = features2.pNext;
    features2.pNext = &device.multiview_features;

    device.variable_pointer_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VARIABLE_POINTER_FEATURES;
    device.variable_pointer_features.pNext = features2.pNext;
    features2.pNext = &device.variable_pointer_features;

    device.protected_memory_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROTECTED_MEMORY_FEATURES;
    device.protected_memory_features.pNext = features2.pNext;
    features2.pNext = &device.protected_memory_features;

    device.sampler_ycbcr_conversion_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SAMPLER_YCBCR_CONVERSION_FEATURES;
    device.sampler_ycbcr_conversion_features.pNext = features2.pNext;
    features2.pNext = &device.sampler_ycbcr_conversion_features;

    device.shader_draw_parameter_features.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_DRAW_PARAMETER_FEATURES;
    device.shader_draw_parameter_features.pNext = features2.pNext;
    features2.pNext = &device.shader_draw_parameter_features;

    vkGetPhysicalDeviceFeatures2(physical_device, &features2);

    VkPhysicalDeviceExternalFenceInfo external_fence_info = {
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_FENCE_INFO, nullptr,
        VK_EXTERNAL_FENCE_HANDLE_TYPE_OPAQUE_FD_BIT};
    VkExternalFenceProperties external_fence_properties = {};

    for (VkExternalFenceHandleTypeFlagBits handle_type =
             VK_EXTERNAL_FENCE_HANDLE_TYPE_OPAQUE_FD_BIT;
         handle_type <= VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT;
         handle_type =
             static_cast<VkExternalFenceHandleTypeFlagBits>(handle_type << 1)) {
      external_fence_info.handleType = handle_type;
      vkGetPhysicalDeviceExternalFenceProperties(
          physical_device, &external_fence_info, &external_fence_properties);
      if (external_fence_properties.exportFromImportedHandleTypes ||
          external_fence_properties.compatibleHandleTypes ||
          external_fence_properties.externalFenceFeatures) {
        device.external_fence_properties.insert(
            std::make_pair(handle_type, external_fence_properties));
      }
    }

    VkPhysicalDeviceExternalSemaphoreInfo external_semaphore_info = {
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_SEMAPHORE_INFO, nullptr,
        VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_OPAQUE_FD_BIT};
    VkExternalSemaphoreProperties external_semaphore_properties = {};

    for (VkExternalSemaphoreHandleTypeFlagBits handle_type =
             VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_OPAQUE_FD_BIT;
         handle_type <= VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
         handle_type = static_cast<VkExternalSemaphoreHandleTypeFlagBits>(
             handle_type << 1)) {
      external_semaphore_info.handleType = handle_type;
      vkGetPhysicalDeviceExternalSemaphoreProperties(
          physical_device, &external_semaphore_info,
          &external_semaphore_properties);
      if (external_semaphore_properties.exportFromImportedHandleTypes ||
          external_semaphore_properties.compatibleHandleTypes ||
          external_semaphore_properties.externalSemaphoreFeatures) {
        device.external_semaphore_properties.insert(
            std::make_pair(handle_type, external_semaphore_properties));
      }
    }
  }

  return device;
}

VkJsonInstance VkJsonGetInstance() {
  VkJsonInstance instance;
  VkResult result;
  uint32_t count;

  count = 0;
  result = vkEnumerateInstanceLayerProperties(&count, nullptr);
  if (result != VK_SUCCESS)
    return VkJsonInstance();
  if (count > 0) {
    std::vector<VkLayerProperties> layers(count);
    result = vkEnumerateInstanceLayerProperties(&count, layers.data());
    if (result != VK_SUCCESS)
      return VkJsonInstance();
    instance.layers.reserve(count);
    for (auto& layer : layers) {
      instance.layers.push_back(VkJsonLayer{layer, std::vector<VkExtensionProperties>()});
      if (!EnumerateExtensions(layer.layerName,
                               &instance.layers.back().extensions))
        return VkJsonInstance();
    }
  }

  if (!EnumerateExtensions(nullptr, &instance.extensions))
    return VkJsonInstance();

  const VkApplicationInfo app_info = {
      VK_STRUCTURE_TYPE_APPLICATION_INFO,
      nullptr,
      "vkjson_info",
      1,
      "",
      0,
      VK_API_VERSION_1_1,
  };
  VkInstanceCreateInfo instance_info = {
      VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
      nullptr,
      0,
      &app_info,
      0,
      nullptr,
      0,
      nullptr,
  };
  VkInstance vkinstance;
  result = vkCreateInstance(&instance_info, nullptr, &vkinstance);
  if (result != VK_SUCCESS)
    return VkJsonInstance();

  count = 0;
  result = vkEnumeratePhysicalDevices(vkinstance, &count, nullptr);
  if (result != VK_SUCCESS) {
    vkDestroyInstance(vkinstance, nullptr);
    return VkJsonInstance();
  }

  std::vector<VkPhysicalDevice> devices(count, VK_NULL_HANDLE);
  result = vkEnumeratePhysicalDevices(vkinstance, &count, devices.data());
  if (result != VK_SUCCESS) {
    vkDestroyInstance(vkinstance, nullptr);
    return VkJsonInstance();
  }

  std::map<VkPhysicalDevice, uint32_t> device_map;
  const uint32_t sz = devices.size();
  instance.devices.reserve(sz);
  for (uint32_t i = 0; i < sz; ++i) {
    device_map.insert(std::make_pair(devices[i], i));
    instance.devices.emplace_back(VkJsonGetDevice(devices[i]));
  }

  result = vkEnumerateInstanceVersion(&instance.api_version);
  if (result != VK_SUCCESS) {
    vkDestroyInstance(vkinstance, nullptr);
    return VkJsonInstance();
  }

  count = 0;
  result = vkEnumeratePhysicalDeviceGroups(vkinstance, &count, nullptr);
  if (result != VK_SUCCESS) {
    vkDestroyInstance(vkinstance, nullptr);
    return VkJsonInstance();
  }

  VkJsonDeviceGroup device_group;
  std::vector<VkPhysicalDeviceGroupProperties> group_properties;
  group_properties.resize(count);
  for (auto& properties : group_properties) {
    properties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GROUP_PROPERTIES;
    properties.pNext = nullptr;
  }
  result = vkEnumeratePhysicalDeviceGroups(vkinstance, &count,
                                           group_properties.data());
  if (result != VK_SUCCESS) {
    vkDestroyInstance(vkinstance, nullptr);
    return VkJsonInstance();
  }
  for (auto properties : group_properties) {
    device_group.properties = properties;
    for (uint32_t i = 0; i < properties.physicalDeviceCount; ++i) {
      device_group.device_inds.push_back(
          device_map[properties.physicalDevices[i]]);
    }
    instance.device_groups.push_back(device_group);
  }

  vkDestroyInstance(vkinstance, nullptr);
  return instance;
}
