/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef LIBVULKAN_DRIVER_GEN_H
#define LIBVULKAN_DRIVER_GEN_H

#include <vulkan/vk_android_native_buffer.h>
#include <vulkan/vulkan.h>

#include <bitset>
#include <optional>
#include <vector>

namespace vulkan {
namespace driver {

struct ProcHook {
    enum Type {
        GLOBAL,
        INSTANCE,
        DEVICE,
    };
    enum Extension {
        ANDROID_native_buffer,
        EXT_debug_report,
        EXT_hdr_metadata,
        EXT_swapchain_colorspace,
        GOOGLE_display_timing,
        GOOGLE_surfaceless_query,
        KHR_android_surface,
        KHR_get_surface_capabilities2,
        KHR_incremental_present,
        KHR_shared_presentable_image,
        KHR_surface,
        KHR_surface_protected_capabilities,
        KHR_swapchain,
        ANDROID_external_memory_android_hardware_buffer,
        KHR_bind_memory2,
        KHR_get_physical_device_properties2,
        KHR_device_group_creation,
        KHR_external_memory_capabilities,
        KHR_external_semaphore_capabilities,
        KHR_external_fence_capabilities,

        EXTENSION_CORE_1_0,
        EXTENSION_CORE_1_1,
        EXTENSION_CORE_1_2,
        EXTENSION_CORE_1_3,
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
    // clang-format off
    PFN_vkDestroyInstance DestroyInstance;
    PFN_vkEnumeratePhysicalDevices EnumeratePhysicalDevices;
    PFN_vkGetInstanceProcAddr GetInstanceProcAddr;
    PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties;
    PFN_vkCreateDevice CreateDevice;
    PFN_vkEnumerateDeviceExtensionProperties EnumerateDeviceExtensionProperties;
    PFN_vkCreateDebugReportCallbackEXT CreateDebugReportCallbackEXT;
    PFN_vkDestroyDebugReportCallbackEXT DestroyDebugReportCallbackEXT;
    PFN_vkDebugReportMessageEXT DebugReportMessageEXT;
    PFN_vkGetPhysicalDeviceFeatures2 GetPhysicalDeviceFeatures2;
    PFN_vkGetPhysicalDeviceFeatures2KHR GetPhysicalDeviceFeatures2KHR;
    PFN_vkGetPhysicalDeviceProperties2 GetPhysicalDeviceProperties2;
    PFN_vkGetPhysicalDeviceProperties2KHR GetPhysicalDeviceProperties2KHR;
    PFN_vkGetPhysicalDeviceFormatProperties2 GetPhysicalDeviceFormatProperties2;
    PFN_vkGetPhysicalDeviceFormatProperties2KHR GetPhysicalDeviceFormatProperties2KHR;
    PFN_vkGetPhysicalDeviceImageFormatProperties2 GetPhysicalDeviceImageFormatProperties2;
    PFN_vkGetPhysicalDeviceImageFormatProperties2KHR GetPhysicalDeviceImageFormatProperties2KHR;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties2 GetPhysicalDeviceQueueFamilyProperties2;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties2KHR GetPhysicalDeviceQueueFamilyProperties2KHR;
    PFN_vkGetPhysicalDeviceMemoryProperties2 GetPhysicalDeviceMemoryProperties2;
    PFN_vkGetPhysicalDeviceMemoryProperties2KHR GetPhysicalDeviceMemoryProperties2KHR;
    PFN_vkGetPhysicalDeviceSparseImageFormatProperties2 GetPhysicalDeviceSparseImageFormatProperties2;
    PFN_vkGetPhysicalDeviceSparseImageFormatProperties2KHR GetPhysicalDeviceSparseImageFormatProperties2KHR;
    PFN_vkGetPhysicalDeviceExternalBufferProperties GetPhysicalDeviceExternalBufferProperties;
    PFN_vkGetPhysicalDeviceExternalBufferPropertiesKHR GetPhysicalDeviceExternalBufferPropertiesKHR;
    PFN_vkGetPhysicalDeviceExternalSemaphoreProperties GetPhysicalDeviceExternalSemaphoreProperties;
    PFN_vkGetPhysicalDeviceExternalSemaphorePropertiesKHR GetPhysicalDeviceExternalSemaphorePropertiesKHR;
    PFN_vkGetPhysicalDeviceExternalFenceProperties GetPhysicalDeviceExternalFenceProperties;
    PFN_vkGetPhysicalDeviceExternalFencePropertiesKHR GetPhysicalDeviceExternalFencePropertiesKHR;
    PFN_vkEnumeratePhysicalDeviceGroups EnumeratePhysicalDeviceGroups;
    PFN_vkEnumeratePhysicalDeviceGroupsKHR EnumeratePhysicalDeviceGroupsKHR;
    // clang-format on
};

struct DeviceDriverTable {
    // clang-format off
    PFN_vkGetDeviceProcAddr GetDeviceProcAddr;
    PFN_vkDestroyDevice DestroyDevice;
    PFN_vkGetDeviceQueue GetDeviceQueue;
    PFN_vkQueueSubmit QueueSubmit;
    PFN_vkCreateImage CreateImage;
    PFN_vkDestroyImage DestroyImage;
    PFN_vkAllocateCommandBuffers AllocateCommandBuffers;
    PFN_vkBindImageMemory2 BindImageMemory2;
    PFN_vkBindImageMemory2KHR BindImageMemory2KHR;
    PFN_vkGetDeviceQueue2 GetDeviceQueue2;
    PFN_vkGetSwapchainGrallocUsageANDROID GetSwapchainGrallocUsageANDROID;
    PFN_vkGetSwapchainGrallocUsage2ANDROID GetSwapchainGrallocUsage2ANDROID;
    PFN_vkGetSwapchainGrallocUsage3ANDROID GetSwapchainGrallocUsage3ANDROID;
    PFN_vkAcquireImageANDROID AcquireImageANDROID;
    PFN_vkQueueSignalReleaseImageANDROID QueueSignalReleaseImageANDROID;
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

std::optional<uint32_t> GetInstanceExtensionPromotedVersion(const char* name);
uint32_t CountPromotedInstanceExtensions(uint32_t begin_version,
                                         uint32_t end_version);
std::vector<const char*> GetPromotedInstanceExtensions(uint32_t begin_version,
                                                       uint32_t end_version);

}  // namespace driver
}  // namespace vulkan

#endif  // LIBVULKAN_DRIVER_TABLE_H
