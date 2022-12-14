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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "driver.h"

#include <dlfcn.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include <SurfaceFlingerProperties.h>
#include <android-base/properties.h>
#include <android/dlext.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>
#include <graphicsenv/GraphicsEnv.h>
#include <log/log.h>
#include <sys/prctl.h>
#include <utils/Timers.h>
#include <utils/Trace.h>
#include <vndksupport/linker.h>

#include <algorithm>
#include <array>
#include <climits>
#include <new>
#include <vector>

#include "stubhal.h"

using namespace android::hardware::configstore;
using namespace android::hardware::configstore::V1_0;

// #define ENABLE_ALLOC_CALLSTACKS 1
#if ENABLE_ALLOC_CALLSTACKS
#include <utils/CallStack.h>
#define ALOGD_CALLSTACK(...)                             \
    do {                                                 \
        ALOGD(__VA_ARGS__);                              \
        android::CallStack callstack;                    \
        callstack.update();                              \
        callstack.log(LOG_TAG, ANDROID_LOG_DEBUG, "  "); \
    } while (false)
#else
#define ALOGD_CALLSTACK(...) \
    do {                     \
    } while (false)
#endif

namespace vulkan {
namespace driver {

namespace {

class Hal {
   public:
    static bool Open();

    static const Hal& Get() { return hal_; }
    static const hwvulkan_device_t& Device() { return *Get().dev_; }

    int GetDebugReportIndex() const { return debug_report_index_; }

   private:
    Hal() : dev_(nullptr), debug_report_index_(-1) {}
    Hal(const Hal&) = delete;
    Hal& operator=(const Hal&) = delete;

    bool ShouldUnloadBuiltinDriver();
    void UnloadBuiltinDriver();
    bool InitDebugReportIndex();

    static Hal hal_;

    const hwvulkan_device_t* dev_;
    int debug_report_index_;
};

class CreateInfoWrapper {
   public:
    CreateInfoWrapper(const VkInstanceCreateInfo& create_info,
                      uint32_t icd_api_version,
                      const VkAllocationCallbacks& allocator);
    CreateInfoWrapper(VkPhysicalDevice physical_dev,
                      const VkDeviceCreateInfo& create_info,
                      uint32_t icd_api_version,
                      const VkAllocationCallbacks& allocator);
    ~CreateInfoWrapper();

    VkResult Validate();

    const std::bitset<ProcHook::EXTENSION_COUNT>& GetHookExtensions() const;
    const std::bitset<ProcHook::EXTENSION_COUNT>& GetHalExtensions() const;

    explicit operator const VkInstanceCreateInfo*() const;
    explicit operator const VkDeviceCreateInfo*() const;

   private:
    struct ExtensionFilter {
        VkExtensionProperties* exts;
        uint32_t ext_count;

        const char** names;
        uint32_t name_count;
        ExtensionFilter()
            : exts(nullptr), ext_count(0), names(nullptr), name_count(0) {}
    };

    VkResult SanitizeApiVersion();
    VkResult SanitizePNext();
    VkResult SanitizeLayers();
    VkResult SanitizeExtensions();

    VkResult QueryExtensionCount(uint32_t& count) const;
    VkResult EnumerateExtensions(uint32_t& count,
                                 VkExtensionProperties* props) const;
    VkResult InitExtensionFilter();
    void FilterExtension(const char* name);

    const bool is_instance_;
    const VkAllocationCallbacks& allocator_;
    const uint32_t loader_api_version_;
    const uint32_t icd_api_version_;

    VkPhysicalDevice physical_dev_;

    union {
        VkInstanceCreateInfo instance_info_;
        VkDeviceCreateInfo dev_info_;
    };

    VkApplicationInfo application_info_;

    ExtensionFilter extension_filter_;

    std::bitset<ProcHook::EXTENSION_COUNT> hook_extensions_;
    std::bitset<ProcHook::EXTENSION_COUNT> hal_extensions_;
};

Hal Hal::hal_;

const std::array<const char*, 2> HAL_SUBNAME_KEY_PROPERTIES = {{
    "ro.hardware.vulkan",
    "ro.board.platform",
}};
constexpr int LIB_DL_FLAGS = RTLD_LOCAL | RTLD_NOW;

// LoadDriver returns:
// * 0 when succeed, or
// * -ENOENT when fail to open binary libraries, or
// * -EINVAL when fail to find HAL_MODULE_INFO_SYM_AS_STR or
//   HWVULKAN_HARDWARE_MODULE_ID in the library.
int LoadDriver(android_namespace_t* library_namespace,
               const hwvulkan_module_t** module) {
    ATRACE_CALL();

    void* so = nullptr;
    for (auto key : HAL_SUBNAME_KEY_PROPERTIES) {
        std::string lib_name = android::base::GetProperty(key, "");
        if (lib_name.empty())
            continue;

        lib_name = "vulkan." + lib_name + ".so";
        if (library_namespace) {
            // load updated driver
            const android_dlextinfo dlextinfo = {
                .flags = ANDROID_DLEXT_USE_NAMESPACE,
                .library_namespace = library_namespace,
            };
            so = android_dlopen_ext(lib_name.c_str(), LIB_DL_FLAGS, &dlextinfo);
            ALOGE("Could not load %s from updatable gfx driver namespace: %s.",
                  lib_name.c_str(), dlerror());
        } else {
            // load built-in driver
            so = android_load_sphal_library(lib_name.c_str(), LIB_DL_FLAGS);
        }
        if (so)
            break;
    }
    if (!so)
        return -ENOENT;

    auto hmi = static_cast<hw_module_t*>(dlsym(so, HAL_MODULE_INFO_SYM_AS_STR));
    if (!hmi) {
        ALOGE("couldn't find symbol '%s' in HAL library: %s", HAL_MODULE_INFO_SYM_AS_STR, dlerror());
        dlclose(so);
        return -EINVAL;
    }
    if (strcmp(hmi->id, HWVULKAN_HARDWARE_MODULE_ID) != 0) {
        ALOGE("HAL id '%s' != '%s'", hmi->id, HWVULKAN_HARDWARE_MODULE_ID);
        dlclose(so);
        return -EINVAL;
    }
    hmi->dso = so;
    *module = reinterpret_cast<const hwvulkan_module_t*>(hmi);
    return 0;
}

int LoadBuiltinDriver(const hwvulkan_module_t** module) {
    ATRACE_CALL();

    android::GraphicsEnv::getInstance().setDriverToLoad(
        android::GpuStatsInfo::Driver::VULKAN);
    return LoadDriver(nullptr, module);
}

int LoadUpdatedDriver(const hwvulkan_module_t** module) {
    ATRACE_CALL();

    auto ns = android::GraphicsEnv::getInstance().getDriverNamespace();
    if (!ns)
        return -ENOENT;
    android::GraphicsEnv::getInstance().setDriverToLoad(
        android::GpuStatsInfo::Driver::VULKAN_UPDATED);
    int result = LoadDriver(ns, module);
    if (result != 0) {
        LOG_ALWAYS_FATAL(
            "couldn't find an updated Vulkan implementation from %s",
            android::GraphicsEnv::getInstance().getDriverPath().c_str());
    }
    return result;
}

bool Hal::Open() {
    ATRACE_CALL();

    const nsecs_t openTime = systemTime();

    if (hal_.ShouldUnloadBuiltinDriver()) {
        hal_.UnloadBuiltinDriver();
    }

    if (hal_.dev_)
        return true;

    // Use a stub device unless we successfully open a real HAL device.
    hal_.dev_ = &stubhal::kDevice;

    int result;
    const hwvulkan_module_t* module = nullptr;

    result = LoadUpdatedDriver(&module);
    if (result == -ENOENT) {
        result = LoadBuiltinDriver(&module);
    }
    if (result != 0) {
        android::GraphicsEnv::getInstance().setDriverLoaded(
            android::GpuStatsInfo::Api::API_VK, false, systemTime() - openTime);
        ALOGV("unable to load Vulkan HAL, using stub HAL (result=%d)", result);
        return true;
    }


    hwvulkan_device_t* device;
    ATRACE_BEGIN("hwvulkan module open");
    result =
        module->common.methods->open(&module->common, HWVULKAN_DEVICE_0,
                                     reinterpret_cast<hw_device_t**>(&device));
    ATRACE_END();
    if (result != 0) {
        android::GraphicsEnv::getInstance().setDriverLoaded(
            android::GpuStatsInfo::Api::API_VK, false, systemTime() - openTime);
        // Any device with a Vulkan HAL should be able to open the device.
        ALOGE("failed to open Vulkan HAL device: %s (%d)", strerror(-result),
              result);
        return false;
    }

    hal_.dev_ = device;

    hal_.InitDebugReportIndex();

    android::GraphicsEnv::getInstance().setDriverLoaded(
        android::GpuStatsInfo::Api::API_VK, true, systemTime() - openTime);

    return true;
}

bool Hal::ShouldUnloadBuiltinDriver() {
    // Should not unload since the driver was not loaded
    if (!hal_.dev_)
        return false;

    // Should not unload if stubhal is used on the device
    if (hal_.dev_ == &stubhal::kDevice)
        return false;

    // Unload the driver if updated driver is chosen
    if (android::GraphicsEnv::getInstance().getDriverNamespace())
        return true;

    return false;
}

void Hal::UnloadBuiltinDriver() {
    ATRACE_CALL();

    ALOGD("Unload builtin Vulkan driver.");

    // Close the opened device
    ALOG_ASSERT(!hal_.dev_->common.close(hal_.dev_->common),
                "hw_device_t::close() failed.");

    // Close the opened shared library in the hw_module_t
    android_unload_sphal_library(hal_.dev_->common.module->dso);

    hal_.dev_ = nullptr;
    hal_.debug_report_index_ = -1;
}

bool Hal::InitDebugReportIndex() {
    ATRACE_CALL();

    uint32_t count;
    if (dev_->EnumerateInstanceExtensionProperties(nullptr, &count, nullptr) !=
        VK_SUCCESS) {
        ALOGE("failed to get HAL instance extension count");
        return false;
    }

    VkExtensionProperties* exts = reinterpret_cast<VkExtensionProperties*>(
        malloc(sizeof(VkExtensionProperties) * count));
    if (!exts) {
        ALOGE("failed to allocate HAL instance extension array");
        return false;
    }

    if (dev_->EnumerateInstanceExtensionProperties(nullptr, &count, exts) !=
        VK_SUCCESS) {
        ALOGE("failed to enumerate HAL instance extensions");
        free(exts);
        return false;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(exts[i].extensionName, VK_EXT_DEBUG_REPORT_EXTENSION_NAME) ==
            0) {
            debug_report_index_ = static_cast<int>(i);
            break;
        }
    }

    free(exts);

    return true;
}

CreateInfoWrapper::CreateInfoWrapper(const VkInstanceCreateInfo& create_info,
                                     uint32_t icd_api_version,
                                     const VkAllocationCallbacks& allocator)
    : is_instance_(true),
      allocator_(allocator),
      loader_api_version_(VK_API_VERSION_1_3),
      icd_api_version_(icd_api_version),
      physical_dev_(VK_NULL_HANDLE),
      instance_info_(create_info),
      extension_filter_() {}

CreateInfoWrapper::CreateInfoWrapper(VkPhysicalDevice physical_dev,
                                     const VkDeviceCreateInfo& create_info,
                                     uint32_t icd_api_version,
                                     const VkAllocationCallbacks& allocator)
    : is_instance_(false),
      allocator_(allocator),
      loader_api_version_(VK_API_VERSION_1_3),
      icd_api_version_(icd_api_version),
      physical_dev_(physical_dev),
      dev_info_(create_info),
      extension_filter_() {}

CreateInfoWrapper::~CreateInfoWrapper() {
    allocator_.pfnFree(allocator_.pUserData, extension_filter_.exts);
    allocator_.pfnFree(allocator_.pUserData, extension_filter_.names);
}

VkResult CreateInfoWrapper::Validate() {
    VkResult result = SanitizeApiVersion();
    if (result == VK_SUCCESS)
        result = SanitizePNext();
    if (result == VK_SUCCESS)
        result = SanitizeLayers();
    if (result == VK_SUCCESS)
        result = SanitizeExtensions();

    return result;
}

const std::bitset<ProcHook::EXTENSION_COUNT>&
CreateInfoWrapper::GetHookExtensions() const {
    return hook_extensions_;
}

const std::bitset<ProcHook::EXTENSION_COUNT>&
CreateInfoWrapper::GetHalExtensions() const {
    return hal_extensions_;
}

CreateInfoWrapper::operator const VkInstanceCreateInfo*() const {
    return &instance_info_;
}

CreateInfoWrapper::operator const VkDeviceCreateInfo*() const {
    return &dev_info_;
}

VkResult CreateInfoWrapper::SanitizeApiVersion() {
    if (!is_instance_ || !instance_info_.pApplicationInfo)
        return VK_SUCCESS;

    if (icd_api_version_ > VK_API_VERSION_1_0 ||
        instance_info_.pApplicationInfo->apiVersion < VK_API_VERSION_1_1)
        return VK_SUCCESS;

    // override apiVersion to avoid error return from 1.0 icd
    application_info_ = *instance_info_.pApplicationInfo;
    application_info_.apiVersion = VK_API_VERSION_1_0;
    instance_info_.pApplicationInfo = &application_info_;

    return VK_SUCCESS;
}

VkResult CreateInfoWrapper::SanitizePNext() {
    const struct StructHeader {
        VkStructureType type;
        const void* next;
    } * header;

    if (is_instance_) {
        header = reinterpret_cast<const StructHeader*>(instance_info_.pNext);

        // skip leading VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFOs
        while (header &&
               header->type == VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO)
            header = reinterpret_cast<const StructHeader*>(header->next);

        instance_info_.pNext = header;
    } else {
        header = reinterpret_cast<const StructHeader*>(dev_info_.pNext);

        // skip leading VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFOs
        while (header &&
               header->type == VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO)
            header = reinterpret_cast<const StructHeader*>(header->next);

        dev_info_.pNext = header;
    }

    return VK_SUCCESS;
}

VkResult CreateInfoWrapper::SanitizeLayers() {
    auto& layer_names = (is_instance_) ? instance_info_.ppEnabledLayerNames
                                       : dev_info_.ppEnabledLayerNames;
    auto& layer_count = (is_instance_) ? instance_info_.enabledLayerCount
                                       : dev_info_.enabledLayerCount;

    // remove all layers
    layer_names = nullptr;
    layer_count = 0;

    return VK_SUCCESS;
}

VkResult CreateInfoWrapper::SanitizeExtensions() {
    auto& ext_names = (is_instance_) ? instance_info_.ppEnabledExtensionNames
                                     : dev_info_.ppEnabledExtensionNames;
    auto& ext_count = (is_instance_) ? instance_info_.enabledExtensionCount
                                     : dev_info_.enabledExtensionCount;

    VkResult result = InitExtensionFilter();
    if (result != VK_SUCCESS)
        return result;

    if (is_instance_ && icd_api_version_ < loader_api_version_) {
        for (uint32_t i = 0; i < ext_count; i++) {
            // Upon api downgrade, skip the promoted instance extensions in the
            // first pass to avoid duplicate extensions.
            const std::optional<uint32_t> version =
                GetInstanceExtensionPromotedVersion(ext_names[i]);
            if (version && *version > icd_api_version_ &&
                *version <= loader_api_version_)
                continue;

            FilterExtension(ext_names[i]);
        }

        // Enable the required extensions to support core functionalities.
        const auto promoted_extensions = GetPromotedInstanceExtensions(
            icd_api_version_, loader_api_version_);
        for (const auto& promoted_extension : promoted_extensions)
            FilterExtension(promoted_extension);
    } else {
        for (uint32_t i = 0; i < ext_count; i++)
            FilterExtension(ext_names[i]);
    }

    // Enable device extensions that contain physical-device commands, so that
    // vkGetInstanceProcAddr will return those physical-device commands.
    if (is_instance_) {
        hook_extensions_.set(ProcHook::KHR_swapchain);
    }

    const uint32_t api_version =
        is_instance_ ? loader_api_version_
                     : std::min(icd_api_version_, loader_api_version_);
    switch (api_version) {
        case VK_API_VERSION_1_3:
            hook_extensions_.set(ProcHook::EXTENSION_CORE_1_3);
            hal_extensions_.set(ProcHook::EXTENSION_CORE_1_3);
            [[clang::fallthrough]];
        case VK_API_VERSION_1_2:
            hook_extensions_.set(ProcHook::EXTENSION_CORE_1_2);
            hal_extensions_.set(ProcHook::EXTENSION_CORE_1_2);
            [[clang::fallthrough]];
        case VK_API_VERSION_1_1:
            hook_extensions_.set(ProcHook::EXTENSION_CORE_1_1);
            hal_extensions_.set(ProcHook::EXTENSION_CORE_1_1);
            [[clang::fallthrough]];
        case VK_API_VERSION_1_0:
            hook_extensions_.set(ProcHook::EXTENSION_CORE_1_0);
            hal_extensions_.set(ProcHook::EXTENSION_CORE_1_0);
            break;
        default:
            ALOGE("Unknown API version[%u]", api_version);
            break;
    }

    ext_names = extension_filter_.names;
    ext_count = extension_filter_.name_count;

    return VK_SUCCESS;
}

VkResult CreateInfoWrapper::QueryExtensionCount(uint32_t& count) const {
    if (is_instance_) {
        return Hal::Device().EnumerateInstanceExtensionProperties(
            nullptr, &count, nullptr);
    } else {
        const auto& driver = GetData(physical_dev_).driver;
        return driver.EnumerateDeviceExtensionProperties(physical_dev_, nullptr,
                                                         &count, nullptr);
    }
}

VkResult CreateInfoWrapper::EnumerateExtensions(
    uint32_t& count,
    VkExtensionProperties* props) const {
    if (is_instance_) {
        return Hal::Device().EnumerateInstanceExtensionProperties(
            nullptr, &count, props);
    } else {
        const auto& driver = GetData(physical_dev_).driver;
        return driver.EnumerateDeviceExtensionProperties(physical_dev_, nullptr,
                                                         &count, props);
    }
}

VkResult CreateInfoWrapper::InitExtensionFilter() {
    // query extension count
    uint32_t count;
    VkResult result = QueryExtensionCount(count);
    if (result != VK_SUCCESS || count == 0)
        return result;

    auto& filter = extension_filter_;
    filter.exts =
        reinterpret_cast<VkExtensionProperties*>(allocator_.pfnAllocation(
            allocator_.pUserData, sizeof(VkExtensionProperties) * count,
            alignof(VkExtensionProperties),
            VK_SYSTEM_ALLOCATION_SCOPE_COMMAND));
    if (!filter.exts)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    // enumerate extensions
    result = EnumerateExtensions(count, filter.exts);
    if (result != VK_SUCCESS && result != VK_INCOMPLETE)
        return result;

    if (!count)
        return VK_SUCCESS;

    filter.ext_count = count;

    // allocate name array
    if (is_instance_) {
        uint32_t enabled_ext_count = instance_info_.enabledExtensionCount;

        // It requires enabling additional promoted extensions to downgrade api,
        // so we reserve enough space here.
        if (icd_api_version_ < loader_api_version_) {
            enabled_ext_count += CountPromotedInstanceExtensions(
                icd_api_version_, loader_api_version_);
        }

        count = std::min(filter.ext_count, enabled_ext_count);
    } else {
        count = std::min(filter.ext_count, dev_info_.enabledExtensionCount);
    }

    if (!count)
        return VK_SUCCESS;

    filter.names = reinterpret_cast<const char**>(allocator_.pfnAllocation(
        allocator_.pUserData, sizeof(const char*) * count, alignof(const char*),
        VK_SYSTEM_ALLOCATION_SCOPE_COMMAND));
    if (!filter.names)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    return VK_SUCCESS;
}

void CreateInfoWrapper::FilterExtension(const char* name) {
    auto& filter = extension_filter_;

    ProcHook::Extension ext_bit = GetProcHookExtension(name);
    if (is_instance_) {
        switch (ext_bit) {
            case ProcHook::KHR_android_surface:
            case ProcHook::KHR_surface:
            case ProcHook::KHR_surface_protected_capabilities:
            case ProcHook::EXT_swapchain_colorspace:
            case ProcHook::KHR_get_surface_capabilities2:
            case ProcHook::GOOGLE_surfaceless_query:
                hook_extensions_.set(ext_bit);
                // return now as these extensions do not require HAL support
                return;
            case ProcHook::EXT_debug_report:
                // both we and HAL can take part in
                hook_extensions_.set(ext_bit);
                break;
            case ProcHook::KHR_get_physical_device_properties2:
            case ProcHook::KHR_device_group_creation:
            case ProcHook::KHR_external_memory_capabilities:
            case ProcHook::KHR_external_semaphore_capabilities:
            case ProcHook::KHR_external_fence_capabilities:
            case ProcHook::EXTENSION_UNKNOWN:
                // Extensions we don't need to do anything about at this level
                break;

            case ProcHook::KHR_bind_memory2:
            case ProcHook::KHR_incremental_present:
            case ProcHook::KHR_shared_presentable_image:
            case ProcHook::KHR_swapchain:
            case ProcHook::EXT_hdr_metadata:
            case ProcHook::ANDROID_external_memory_android_hardware_buffer:
            case ProcHook::ANDROID_native_buffer:
            case ProcHook::GOOGLE_display_timing:
            case ProcHook::EXTENSION_CORE_1_0:
            case ProcHook::EXTENSION_CORE_1_1:
            case ProcHook::EXTENSION_CORE_1_2:
            case ProcHook::EXTENSION_CORE_1_3:
            case ProcHook::EXTENSION_COUNT:
                // Device and meta extensions. If we ever get here it's a bug in
                // our code. But enumerating them lets us avoid having a default
                // case, and default hides other bugs.
                ALOGE(
                    "CreateInfoWrapper::FilterExtension: invalid instance "
                    "extension '%s'. FIX ME",
                    name);
                return;

            // Don't use a default case. Without it, -Wswitch will tell us
            // at compile time if someone adds a new ProcHook extension but
            // doesn't handle it above. That's a real bug that has
            // not-immediately-obvious effects.
            //
            // default:
            //     break;
        }
    } else {
        switch (ext_bit) {
            case ProcHook::KHR_swapchain:
                // map VK_KHR_swapchain to VK_ANDROID_native_buffer
                name = VK_ANDROID_NATIVE_BUFFER_EXTENSION_NAME;
                ext_bit = ProcHook::ANDROID_native_buffer;
                break;
            case ProcHook::KHR_incremental_present:
            case ProcHook::GOOGLE_display_timing:
            case ProcHook::KHR_shared_presentable_image:
                hook_extensions_.set(ext_bit);
                // return now as these extensions do not require HAL support
                return;
            case ProcHook::EXT_hdr_metadata:
            case ProcHook::KHR_bind_memory2:
                hook_extensions_.set(ext_bit);
                break;
            case ProcHook::ANDROID_external_memory_android_hardware_buffer:
            case ProcHook::EXTENSION_UNKNOWN:
                // Extensions we don't need to do anything about at this level
                break;

            case ProcHook::KHR_android_surface:
            case ProcHook::KHR_get_physical_device_properties2:
            case ProcHook::KHR_device_group_creation:
            case ProcHook::KHR_external_memory_capabilities:
            case ProcHook::KHR_external_semaphore_capabilities:
            case ProcHook::KHR_external_fence_capabilities:
            case ProcHook::KHR_get_surface_capabilities2:
            case ProcHook::KHR_surface:
            case ProcHook::KHR_surface_protected_capabilities:
            case ProcHook::EXT_debug_report:
            case ProcHook::EXT_swapchain_colorspace:
            case ProcHook::GOOGLE_surfaceless_query:
            case ProcHook::ANDROID_native_buffer:
            case ProcHook::EXTENSION_CORE_1_0:
            case ProcHook::EXTENSION_CORE_1_1:
            case ProcHook::EXTENSION_CORE_1_2:
            case ProcHook::EXTENSION_CORE_1_3:
            case ProcHook::EXTENSION_COUNT:
                // Instance and meta extensions. If we ever get here it's a bug
                // in our code. But enumerating them lets us avoid having a
                // default case, and default hides other bugs.
                ALOGE(
                    "CreateInfoWrapper::FilterExtension: invalid device "
                    "extension '%s'. FIX ME",
                    name);
                return;

            // Don't use a default case. Without it, -Wswitch will tell us
            // at compile time if someone adds a new ProcHook extension but
            // doesn't handle it above. That's a real bug that has
            // not-immediately-obvious effects.
            //
            // default:
            //     break;
        }
    }

    for (uint32_t i = 0; i < filter.ext_count; i++) {
        const VkExtensionProperties& props = filter.exts[i];
        // ignore unknown extensions
        if (strcmp(name, props.extensionName) != 0)
            continue;

        filter.names[filter.name_count++] = name;
        if (ext_bit != ProcHook::EXTENSION_UNKNOWN) {
            if (ext_bit == ProcHook::ANDROID_native_buffer)
                hook_extensions_.set(ProcHook::KHR_swapchain);

            hal_extensions_.set(ext_bit);
        }

        break;
    }
}

VKAPI_ATTR void* DefaultAllocate(void*,
                                 size_t size,
                                 size_t alignment,
                                 VkSystemAllocationScope) {
    void* ptr = nullptr;
    // Vulkan requires 'alignment' to be a power of two, but posix_memalign
    // additionally requires that it be at least sizeof(void*).
    int ret = posix_memalign(&ptr, std::max(alignment, sizeof(void*)), size);
    ALOGD_CALLSTACK("Allocate: size=%zu align=%zu => (%d) %p", size, alignment,
                    ret, ptr);
    return ret == 0 ? ptr : nullptr;
}

VKAPI_ATTR void* DefaultReallocate(void*,
                                   void* ptr,
                                   size_t size,
                                   size_t alignment,
                                   VkSystemAllocationScope) {
    if (size == 0) {
        free(ptr);
        return nullptr;
    }

    // TODO(b/143295633): Right now we never shrink allocations; if the new
    // request is smaller than the existing chunk, we just continue using it.
    // Right now the loader never reallocs, so this doesn't matter. If that
    // changes, or if this code is copied into some other project, this should
    // probably have a heuristic to allocate-copy-free when doing so will save
    // "enough" space.
    size_t old_size = ptr ? malloc_usable_size(ptr) : 0;
    if (size <= old_size)
        return ptr;

    void* new_ptr = nullptr;
    if (posix_memalign(&new_ptr, std::max(alignment, sizeof(void*)), size) != 0)
        return nullptr;
    if (ptr) {
        memcpy(new_ptr, ptr, std::min(old_size, size));
        free(ptr);
    }
    return new_ptr;
}

VKAPI_ATTR void DefaultFree(void*, void* ptr) {
    ALOGD_CALLSTACK("Free: %p", ptr);
    free(ptr);
}

InstanceData* AllocateInstanceData(const VkAllocationCallbacks& allocator) {
    void* data_mem = allocator.pfnAllocation(
        allocator.pUserData, sizeof(InstanceData), alignof(InstanceData),
        VK_SYSTEM_ALLOCATION_SCOPE_INSTANCE);
    if (!data_mem)
        return nullptr;

    return new (data_mem) InstanceData(allocator);
}

void FreeInstanceData(InstanceData* data,
                      const VkAllocationCallbacks& allocator) {
    data->~InstanceData();
    allocator.pfnFree(allocator.pUserData, data);
}

DeviceData* AllocateDeviceData(
    const VkAllocationCallbacks& allocator,
    const DebugReportCallbackList& debug_report_callbacks) {
    void* data_mem = allocator.pfnAllocation(
        allocator.pUserData, sizeof(DeviceData), alignof(DeviceData),
        VK_SYSTEM_ALLOCATION_SCOPE_DEVICE);
    if (!data_mem)
        return nullptr;

    return new (data_mem) DeviceData(allocator, debug_report_callbacks);
}

void FreeDeviceData(DeviceData* data, const VkAllocationCallbacks& allocator) {
    data->~DeviceData();
    allocator.pfnFree(allocator.pUserData, data);
}

}  // anonymous namespace

bool OpenHAL() {
    return Hal::Open();
}

const VkAllocationCallbacks& GetDefaultAllocator() {
    static const VkAllocationCallbacks kDefaultAllocCallbacks = {
        .pUserData = nullptr,
        .pfnAllocation = DefaultAllocate,
        .pfnReallocation = DefaultReallocate,
        .pfnFree = DefaultFree,
    };

    return kDefaultAllocCallbacks;
}

PFN_vkVoidFunction GetInstanceProcAddr(VkInstance instance, const char* pName) {
    const ProcHook* hook = GetProcHook(pName);
    if (!hook)
        return Hal::Device().GetInstanceProcAddr(instance, pName);

    if (!instance) {
        if (hook->type == ProcHook::GLOBAL)
            return hook->proc;

        // v0 layers expect
        //
        //   vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkCreateDevice");
        //
        // to work.
        if (strcmp(pName, "vkCreateDevice") == 0)
            return hook->proc;

        ALOGE(
            "internal vkGetInstanceProcAddr called for %s without an instance",
            pName);

        return nullptr;
    }

    PFN_vkVoidFunction proc;

    switch (hook->type) {
        case ProcHook::INSTANCE:
            proc = (GetData(instance).hook_extensions[hook->extension])
                       ? hook->proc
                       : nullptr;
            break;
        case ProcHook::DEVICE:
            proc = (hook->extension == ProcHook::EXTENSION_CORE_1_0)
                       ? hook->proc
                       : hook->checked_proc;
            break;
        default:
            ALOGE(
                "internal vkGetInstanceProcAddr called for %s with an instance",
                pName);
            proc = nullptr;
            break;
    }

    return proc;
}

PFN_vkVoidFunction GetDeviceProcAddr(VkDevice device, const char* pName) {
    const ProcHook* hook = GetProcHook(pName);
    if (!hook)
        return GetData(device).driver.GetDeviceProcAddr(device, pName);

    if (hook->type != ProcHook::DEVICE) {
        ALOGE("internal vkGetDeviceProcAddr called for %s", pName);
        return nullptr;
    }

    return (GetData(device).hook_extensions[hook->extension]) ? hook->proc
                                                              : nullptr;
}

VkResult EnumerateInstanceExtensionProperties(
    const char* pLayerName,
    uint32_t* pPropertyCount,
    VkExtensionProperties* pProperties) {
    std::vector<VkExtensionProperties> loader_extensions;
    loader_extensions.push_back(
        {VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_SURFACE_SPEC_VERSION});
    loader_extensions.push_back(
        {VK_KHR_SURFACE_PROTECTED_CAPABILITIES_EXTENSION_NAME,
         VK_KHR_SURFACE_PROTECTED_CAPABILITIES_SPEC_VERSION});
    loader_extensions.push_back({
        VK_KHR_ANDROID_SURFACE_EXTENSION_NAME,
        VK_KHR_ANDROID_SURFACE_SPEC_VERSION});
    loader_extensions.push_back({
        VK_EXT_SWAPCHAIN_COLOR_SPACE_EXTENSION_NAME,
        VK_EXT_SWAPCHAIN_COLOR_SPACE_SPEC_VERSION});
    loader_extensions.push_back(
        {VK_KHR_GET_SURFACE_CAPABILITIES_2_EXTENSION_NAME,
         VK_KHR_GET_SURFACE_CAPABILITIES_2_SPEC_VERSION});
    loader_extensions.push_back({VK_GOOGLE_SURFACELESS_QUERY_EXTENSION_NAME,
                                 VK_GOOGLE_SURFACELESS_QUERY_SPEC_VERSION});

    static const VkExtensionProperties loader_debug_report_extension = {
        VK_EXT_DEBUG_REPORT_EXTENSION_NAME, VK_EXT_DEBUG_REPORT_SPEC_VERSION,
    };

    // enumerate our extensions first
    if (!pLayerName && pProperties) {
        uint32_t count = std::min(
            *pPropertyCount, static_cast<uint32_t>(loader_extensions.size()));

        std::copy_n(loader_extensions.data(), count, pProperties);

        if (count < loader_extensions.size()) {
            *pPropertyCount = count;
            return VK_INCOMPLETE;
        }

        pProperties += count;
        *pPropertyCount -= count;

        if (Hal::Get().GetDebugReportIndex() < 0) {
            if (!*pPropertyCount) {
                *pPropertyCount = count;
                return VK_INCOMPLETE;
            }

            pProperties[0] = loader_debug_report_extension;
            pProperties += 1;
            *pPropertyCount -= 1;
        }
    }

    ATRACE_BEGIN("driver.EnumerateInstanceExtensionProperties");
    VkResult result = Hal::Device().EnumerateInstanceExtensionProperties(
        pLayerName, pPropertyCount, pProperties);
    ATRACE_END();

    if (!pLayerName && (result == VK_SUCCESS || result == VK_INCOMPLETE)) {
        int idx = Hal::Get().GetDebugReportIndex();
        if (idx < 0) {
            *pPropertyCount += 1;
        } else if (pProperties &&
                   static_cast<uint32_t>(idx) < *pPropertyCount) {
            pProperties[idx].specVersion =
                std::min(pProperties[idx].specVersion,
                         loader_debug_report_extension.specVersion);
        }

        *pPropertyCount += loader_extensions.size();
    }

    return result;
}

void QueryPresentationProperties(
    VkPhysicalDevice physicalDevice,
    VkPhysicalDevicePresentationPropertiesANDROID* presentation_properties) {
    ATRACE_CALL();

    // Request the android-specific presentation properties via GPDP2
    VkPhysicalDeviceProperties2 properties = {
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
        presentation_properties,
        {},
    };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
    presentation_properties->sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENTATION_PROPERTIES_ANDROID;
#pragma clang diagnostic pop
    presentation_properties->pNext = nullptr;
    presentation_properties->sharedImage = VK_FALSE;

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceProperties2) {
        // >= 1.1 driver, supports core GPDP2 entrypoint.
        driver.GetPhysicalDeviceProperties2(physicalDevice, &properties);
    } else if (driver.GetPhysicalDeviceProperties2KHR) {
        // Old driver, but may support presentation properties
        // if we have the GPDP2 extension. Otherwise, no presentation
        // properties supported.
        driver.GetPhysicalDeviceProperties2KHR(physicalDevice, &properties);
    }
}

VkResult GetAndroidNativeBufferSpecVersion9Support(
    VkPhysicalDevice physicalDevice,
    bool& support) {
    support = false;

    const InstanceData& data = GetData(physicalDevice);

    // Call to get propertyCount
    uint32_t propertyCount = 0;
    ATRACE_BEGIN("driver.EnumerateDeviceExtensionProperties");
    VkResult result = data.driver.EnumerateDeviceExtensionProperties(
        physicalDevice, nullptr, &propertyCount, nullptr);
    ATRACE_END();

    if (result != VK_SUCCESS && result != VK_INCOMPLETE) {
        return result;
    }

    // Call to enumerate properties
    std::vector<VkExtensionProperties> properties(propertyCount);
    ATRACE_BEGIN("driver.EnumerateDeviceExtensionProperties");
    result = data.driver.EnumerateDeviceExtensionProperties(
        physicalDevice, nullptr, &propertyCount, properties.data());
    ATRACE_END();

    if (result != VK_SUCCESS && result != VK_INCOMPLETE) {
        return result;
    }

    for (uint32_t i = 0; i < propertyCount; i++) {
        auto& prop = properties[i];

        if (strcmp(prop.extensionName,
                   VK_ANDROID_NATIVE_BUFFER_EXTENSION_NAME) != 0)
            continue;

        if (prop.specVersion >= 9) {
            support = true;
            return result;
        }
    }

    return result;
}

VkResult EnumerateDeviceExtensionProperties(
    VkPhysicalDevice physicalDevice,
    const char* pLayerName,
    uint32_t* pPropertyCount,
    VkExtensionProperties* pProperties) {
    const InstanceData& data = GetData(physicalDevice);
    // extensions that are unconditionally exposed by the loader
    std::vector<VkExtensionProperties> loader_extensions;
    loader_extensions.push_back({
        VK_KHR_INCREMENTAL_PRESENT_EXTENSION_NAME,
        VK_KHR_INCREMENTAL_PRESENT_SPEC_VERSION});

    bool hdrBoardConfig = android::sysprop::has_HDR_display(false);
    if (hdrBoardConfig) {
        loader_extensions.push_back({VK_EXT_HDR_METADATA_EXTENSION_NAME,
                                     VK_EXT_HDR_METADATA_SPEC_VERSION});
    }

    VkPhysicalDevicePresentationPropertiesANDROID presentation_properties;
    QueryPresentationProperties(physicalDevice, &presentation_properties);
    if (presentation_properties.sharedImage) {
        loader_extensions.push_back({
            VK_KHR_SHARED_PRESENTABLE_IMAGE_EXTENSION_NAME,
            VK_KHR_SHARED_PRESENTABLE_IMAGE_SPEC_VERSION});
    }

    // conditionally add VK_GOOGLE_display_timing if present timestamps are
    // supported by the driver:
    if (android::base::GetBoolProperty("service.sf.present_timestamp", false)) {
        loader_extensions.push_back({
                VK_GOOGLE_DISPLAY_TIMING_EXTENSION_NAME,
                VK_GOOGLE_DISPLAY_TIMING_SPEC_VERSION});
    }

    // Conditionally add VK_EXT_IMAGE_COMPRESSION_CONTROL* if feature and ANB
    // support is provided by the driver
    VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT
        swapchainCompFeats = {};
    swapchainCompFeats.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_FEATURES_EXT;
    swapchainCompFeats.pNext = nullptr;
    swapchainCompFeats.imageCompressionControlSwapchain = false;
    VkPhysicalDeviceImageCompressionControlFeaturesEXT imageCompFeats = {};
    imageCompFeats.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_FEATURES_EXT;
    imageCompFeats.pNext = &swapchainCompFeats;
    imageCompFeats.imageCompressionControl = false;

    VkPhysicalDeviceFeatures2 feats2 = {};
    feats2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    feats2.pNext = &imageCompFeats;

    const auto& driver = GetData(physicalDevice).driver;
    if (driver.GetPhysicalDeviceFeatures2 ||
        driver.GetPhysicalDeviceFeatures2KHR) {
        GetPhysicalDeviceFeatures2(physicalDevice, &feats2);
    }

    bool anb9 = false;
    VkResult result =
        GetAndroidNativeBufferSpecVersion9Support(physicalDevice, anb9);

    if (result != VK_SUCCESS && result != VK_INCOMPLETE) {
        return result;
    }

    if (anb9 && imageCompFeats.imageCompressionControl) {
        loader_extensions.push_back(
            {VK_EXT_IMAGE_COMPRESSION_CONTROL_EXTENSION_NAME,
             VK_EXT_IMAGE_COMPRESSION_CONTROL_SPEC_VERSION});
    }
    if (anb9 && swapchainCompFeats.imageCompressionControlSwapchain) {
        loader_extensions.push_back(
            {VK_EXT_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_EXTENSION_NAME,
             VK_EXT_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_SPEC_VERSION});
    }

    // enumerate our extensions first
    if (!pLayerName && pProperties) {
        uint32_t count = std::min(
            *pPropertyCount, static_cast<uint32_t>(loader_extensions.size()));

        std::copy_n(loader_extensions.data(), count, pProperties);

        if (count < loader_extensions.size()) {
            *pPropertyCount = count;
            return VK_INCOMPLETE;
        }

        pProperties += count;
        *pPropertyCount -= count;
    }

    ATRACE_BEGIN("driver.EnumerateDeviceExtensionProperties");
    result = data.driver.EnumerateDeviceExtensionProperties(
        physicalDevice, pLayerName, pPropertyCount, pProperties);
    ATRACE_END();

    if (pProperties) {
        // map VK_ANDROID_native_buffer to VK_KHR_swapchain
        for (uint32_t i = 0; i < *pPropertyCount; i++) {
            auto& prop = pProperties[i];

            if (strcmp(prop.extensionName,
                       VK_ANDROID_NATIVE_BUFFER_EXTENSION_NAME) != 0)
                continue;

            memcpy(prop.extensionName, VK_KHR_SWAPCHAIN_EXTENSION_NAME,
                   sizeof(VK_KHR_SWAPCHAIN_EXTENSION_NAME));

            if (prop.specVersion >= 8) {
                prop.specVersion = VK_KHR_SWAPCHAIN_SPEC_VERSION;
            } else {
                prop.specVersion = 68;
            }
        }
    }

    // restore loader extension count
    if (!pLayerName && (result == VK_SUCCESS || result == VK_INCOMPLETE)) {
        *pPropertyCount += loader_extensions.size();
    }

    return result;
}

VkResult CreateInstance(const VkInstanceCreateInfo* pCreateInfo,
                        const VkAllocationCallbacks* pAllocator,
                        VkInstance* pInstance) {
    const VkAllocationCallbacks& data_allocator =
        (pAllocator) ? *pAllocator : GetDefaultAllocator();

    VkResult result = VK_SUCCESS;
    uint32_t icd_api_version = VK_API_VERSION_1_0;
    PFN_vkEnumerateInstanceVersion pfn_enumerate_instance_version =
        reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
            Hal::Device().GetInstanceProcAddr(nullptr,
                                              "vkEnumerateInstanceVersion"));
    if (pfn_enumerate_instance_version) {
        ATRACE_BEGIN("pfn_enumerate_instance_version");
        result = (*pfn_enumerate_instance_version)(&icd_api_version);
        ATRACE_END();
        if (result != VK_SUCCESS)
            return result;

        icd_api_version ^= VK_API_VERSION_PATCH(icd_api_version);
    }

    CreateInfoWrapper wrapper(*pCreateInfo, icd_api_version, data_allocator);
    result = wrapper.Validate();
    if (result != VK_SUCCESS)
        return result;

    InstanceData* data = AllocateInstanceData(data_allocator);
    if (!data)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    data->hook_extensions |= wrapper.GetHookExtensions();

    // call into the driver
    VkInstance instance;
    ATRACE_BEGIN("driver.CreateInstance");
    result = Hal::Device().CreateInstance(
        static_cast<const VkInstanceCreateInfo*>(wrapper), pAllocator,
        &instance);
    ATRACE_END();
    if (result != VK_SUCCESS) {
        FreeInstanceData(data, data_allocator);
        return result;
    }

    // initialize InstanceDriverTable
    if (!SetData(instance, *data) ||
        !InitDriverTable(instance, Hal::Device().GetInstanceProcAddr,
                         wrapper.GetHalExtensions())) {
        data->driver.DestroyInstance = reinterpret_cast<PFN_vkDestroyInstance>(
            Hal::Device().GetInstanceProcAddr(instance, "vkDestroyInstance"));
        if (data->driver.DestroyInstance)
            data->driver.DestroyInstance(instance, pAllocator);

        FreeInstanceData(data, data_allocator);

        return VK_ERROR_INCOMPATIBLE_DRIVER;
    }

    data->get_device_proc_addr = reinterpret_cast<PFN_vkGetDeviceProcAddr>(
        Hal::Device().GetInstanceProcAddr(instance, "vkGetDeviceProcAddr"));
    if (!data->get_device_proc_addr) {
        data->driver.DestroyInstance(instance, pAllocator);
        FreeInstanceData(data, data_allocator);

        return VK_ERROR_INCOMPATIBLE_DRIVER;
    }

    *pInstance = instance;

    return VK_SUCCESS;
}

void DestroyInstance(VkInstance instance,
                     const VkAllocationCallbacks* pAllocator) {
    InstanceData& data = GetData(instance);
    data.driver.DestroyInstance(instance, pAllocator);

    VkAllocationCallbacks local_allocator;
    if (!pAllocator) {
        local_allocator = data.allocator;
        pAllocator = &local_allocator;
    }

    FreeInstanceData(&data, *pAllocator);
}

VkResult CreateDevice(VkPhysicalDevice physicalDevice,
                      const VkDeviceCreateInfo* pCreateInfo,
                      const VkAllocationCallbacks* pAllocator,
                      VkDevice* pDevice) {
    const InstanceData& instance_data = GetData(physicalDevice);
    const VkAllocationCallbacks& data_allocator =
        (pAllocator) ? *pAllocator : instance_data.allocator;

    VkPhysicalDeviceProperties properties;
    ATRACE_BEGIN("driver.GetPhysicalDeviceProperties");
    instance_data.driver.GetPhysicalDeviceProperties(physicalDevice,
                                                     &properties);
    ATRACE_END();

    CreateInfoWrapper wrapper(
        physicalDevice, *pCreateInfo,
        properties.apiVersion ^ VK_API_VERSION_PATCH(properties.apiVersion),
        data_allocator);
    VkResult result = wrapper.Validate();
    if (result != VK_SUCCESS)
        return result;

    ATRACE_BEGIN("AllocateDeviceData");
    DeviceData* data = AllocateDeviceData(data_allocator,
                                          instance_data.debug_report_callbacks);
    ATRACE_END();
    if (!data)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    data->hook_extensions |= wrapper.GetHookExtensions();

    // call into the driver
    VkDevice dev;
    ATRACE_BEGIN("driver.CreateDevice");
    result = instance_data.driver.CreateDevice(
        physicalDevice, static_cast<const VkDeviceCreateInfo*>(wrapper),
        pAllocator, &dev);
    ATRACE_END();
    if (result != VK_SUCCESS) {
        FreeDeviceData(data, data_allocator);
        return result;
    }

    // initialize DeviceDriverTable
    if (!SetData(dev, *data) ||
        !InitDriverTable(dev, instance_data.get_device_proc_addr,
                         wrapper.GetHalExtensions())) {
        data->driver.DestroyDevice = reinterpret_cast<PFN_vkDestroyDevice>(
            instance_data.get_device_proc_addr(dev, "vkDestroyDevice"));
        if (data->driver.DestroyDevice)
            data->driver.DestroyDevice(dev, pAllocator);

        FreeDeviceData(data, data_allocator);

        return VK_ERROR_INCOMPATIBLE_DRIVER;
    }

    // Confirming ANDROID_native_buffer implementation, whose set of
    // entrypoints varies according to the spec version.
    if ((wrapper.GetHalExtensions()[ProcHook::ANDROID_native_buffer]) &&
        !data->driver.GetSwapchainGrallocUsageANDROID &&
        !data->driver.GetSwapchainGrallocUsage2ANDROID &&
        !data->driver.GetSwapchainGrallocUsage3ANDROID) {
        ALOGE(
            "Driver's implementation of ANDROID_native_buffer is broken;"
            " must expose at least one of "
            "vkGetSwapchainGrallocUsageANDROID or "
            "vkGetSwapchainGrallocUsage2ANDROID or "
            "vkGetSwapchainGrallocUsage3ANDROID");

        data->driver.DestroyDevice(dev, pAllocator);
        FreeDeviceData(data, data_allocator);

        return VK_ERROR_INCOMPATIBLE_DRIVER;
    }

    if (properties.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU) {
        // Log that the app is hitting software Vulkan implementation
        android::GraphicsEnv::getInstance().setTargetStats(
            android::GpuStatsInfo::Stats::CPU_VULKAN_IN_USE);
    }

    data->driver_device = dev;

    *pDevice = dev;

    return VK_SUCCESS;
}

void DestroyDevice(VkDevice device, const VkAllocationCallbacks* pAllocator) {
    DeviceData& data = GetData(device);
    data.driver.DestroyDevice(device, pAllocator);

    VkAllocationCallbacks local_allocator;
    if (!pAllocator) {
        local_allocator = data.allocator;
        pAllocator = &local_allocator;
    }

    FreeDeviceData(&data, *pAllocator);
}

VkResult EnumeratePhysicalDevices(VkInstance instance,
                                  uint32_t* pPhysicalDeviceCount,
                                  VkPhysicalDevice* pPhysicalDevices) {
    ATRACE_CALL();

    const auto& data = GetData(instance);

    VkResult result = data.driver.EnumeratePhysicalDevices(
        instance, pPhysicalDeviceCount, pPhysicalDevices);
    if ((result == VK_SUCCESS || result == VK_INCOMPLETE) && pPhysicalDevices) {
        for (uint32_t i = 0; i < *pPhysicalDeviceCount; i++)
            SetData(pPhysicalDevices[i], data);
    }

    return result;
}

VkResult EnumeratePhysicalDeviceGroups(
    VkInstance instance,
    uint32_t* pPhysicalDeviceGroupCount,
    VkPhysicalDeviceGroupProperties* pPhysicalDeviceGroupProperties) {
    ATRACE_CALL();

    VkResult result = VK_SUCCESS;
    const auto& data = GetData(instance);

    if (!data.driver.EnumeratePhysicalDeviceGroups &&
        !data.driver.EnumeratePhysicalDeviceGroupsKHR) {
        uint32_t device_count = 0;
        result = EnumeratePhysicalDevices(instance, &device_count, nullptr);
        if (result < 0)
            return result;

        if (!pPhysicalDeviceGroupProperties) {
            *pPhysicalDeviceGroupCount = device_count;
            return result;
        }

        if (!device_count) {
            *pPhysicalDeviceGroupCount = 0;
            return result;
        }
        device_count = std::min(device_count, *pPhysicalDeviceGroupCount);
        if (!device_count)
            return VK_INCOMPLETE;

        std::vector<VkPhysicalDevice> devices(device_count);
        *pPhysicalDeviceGroupCount = device_count;
        result =
            EnumeratePhysicalDevices(instance, &device_count, devices.data());
        if (result < 0)
            return result;

        for (uint32_t i = 0; i < device_count; ++i) {
            pPhysicalDeviceGroupProperties[i].physicalDeviceCount = 1;
            pPhysicalDeviceGroupProperties[i].physicalDevices[0] = devices[i];
            pPhysicalDeviceGroupProperties[i].subsetAllocation = 0;
        }
    } else {
        if (data.driver.EnumeratePhysicalDeviceGroups) {
            result = data.driver.EnumeratePhysicalDeviceGroups(
                instance, pPhysicalDeviceGroupCount,
                pPhysicalDeviceGroupProperties);
        } else {
            result = data.driver.EnumeratePhysicalDeviceGroupsKHR(
                instance, pPhysicalDeviceGroupCount,
                pPhysicalDeviceGroupProperties);
        }
        if ((result == VK_SUCCESS || result == VK_INCOMPLETE) &&
            *pPhysicalDeviceGroupCount && pPhysicalDeviceGroupProperties) {
            for (uint32_t i = 0; i < *pPhysicalDeviceGroupCount; i++) {
                for (uint32_t j = 0;
                     j < pPhysicalDeviceGroupProperties[i].physicalDeviceCount;
                     j++) {
                    SetData(
                        pPhysicalDeviceGroupProperties[i].physicalDevices[j],
                        data);
                }
            }
        }
    }

    return result;
}

void GetDeviceQueue(VkDevice device,
                    uint32_t queueFamilyIndex,
                    uint32_t queueIndex,
                    VkQueue* pQueue) {
    ATRACE_CALL();

    const auto& data = GetData(device);

    data.driver.GetDeviceQueue(device, queueFamilyIndex, queueIndex, pQueue);
    SetData(*pQueue, data);
}

void GetDeviceQueue2(VkDevice device,
                     const VkDeviceQueueInfo2* pQueueInfo,
                     VkQueue* pQueue) {
    ATRACE_CALL();

    const auto& data = GetData(device);

    data.driver.GetDeviceQueue2(device, pQueueInfo, pQueue);
    if (*pQueue != VK_NULL_HANDLE) SetData(*pQueue, data);
}

VkResult AllocateCommandBuffers(
    VkDevice device,
    const VkCommandBufferAllocateInfo* pAllocateInfo,
    VkCommandBuffer* pCommandBuffers) {
    ATRACE_CALL();

    const auto& data = GetData(device);

    VkResult result = data.driver.AllocateCommandBuffers(device, pAllocateInfo,
                                                         pCommandBuffers);
    if (result == VK_SUCCESS) {
        for (uint32_t i = 0; i < pAllocateInfo->commandBufferCount; i++)
            SetData(pCommandBuffers[i], data);
    }

    return result;
}

VkResult QueueSubmit(VkQueue queue,
                     uint32_t submitCount,
                     const VkSubmitInfo* pSubmits,
                     VkFence fence) {
    ATRACE_CALL();

    const auto& data = GetData(queue);

    return data.driver.QueueSubmit(queue, submitCount, pSubmits, fence);
}

void GetPhysicalDeviceFeatures2(VkPhysicalDevice physicalDevice,
                                VkPhysicalDeviceFeatures2* pFeatures) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceFeatures2) {
        driver.GetPhysicalDeviceFeatures2(physicalDevice, pFeatures);
    } else {
        driver.GetPhysicalDeviceFeatures2KHR(physicalDevice, pFeatures);
    }

    // Conditionally add imageCompressionControlSwapchain if
    // imageCompressionControl is supported Check for imageCompressionControl in
    // the pChain
    bool imageCompressionControl = false;
    bool imageCompressionControlInChain = false;
    bool imageCompressionControlSwapchainInChain = false;
    VkPhysicalDeviceFeatures2* pFeats = pFeatures;
    while (pFeats) {
        switch (pFeats->sType) {
            case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_FEATURES_EXT: {
                const VkPhysicalDeviceImageCompressionControlFeaturesEXT*
                    compressionFeat = reinterpret_cast<
                        const VkPhysicalDeviceImageCompressionControlFeaturesEXT*>(
                        pFeats);
                imageCompressionControl =
                    compressionFeat->imageCompressionControl;
                imageCompressionControlInChain = true;
            } break;

            case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_FEATURES_EXT: {
                VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT*
                    compressionFeat = reinterpret_cast<
                        VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT*>(
                        pFeats);
                compressionFeat->imageCompressionControlSwapchain = false;
                imageCompressionControlSwapchainInChain = true;
            } break;

            default:
                break;
        }
        pFeats = reinterpret_cast<VkPhysicalDeviceFeatures2*>(pFeats->pNext);
    }

    if (!imageCompressionControlSwapchainInChain) {
        return;
    }

    // If not in pchain, explicitly query for imageCompressionControl
    if (!imageCompressionControlInChain) {
        VkPhysicalDeviceImageCompressionControlFeaturesEXT imageCompFeats = {};
        imageCompFeats.sType =
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_FEATURES_EXT;
        imageCompFeats.pNext = nullptr;
        imageCompFeats.imageCompressionControl = false;

        VkPhysicalDeviceFeatures2 feats2 = {};
        feats2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
        feats2.pNext = &imageCompFeats;

        if (driver.GetPhysicalDeviceFeatures2) {
            driver.GetPhysicalDeviceFeatures2(physicalDevice, &feats2);
        } else {
            driver.GetPhysicalDeviceFeatures2KHR(physicalDevice, &feats2);
        }

        imageCompressionControl = imageCompFeats.imageCompressionControl;
    }

    // Only enumerate imageCompressionControlSwapchin if imageCompressionControl
    if (imageCompressionControl) {
        pFeats = pFeatures;
        while (pFeats) {
            switch (pFeats->sType) {
                case VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_FEATURES_EXT: {
                    VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT*
                        compressionFeat = reinterpret_cast<
                            VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT*>(
                            pFeats);
                    compressionFeat->imageCompressionControlSwapchain = true;
                } break;

                default:
                    break;
            }
            pFeats =
                reinterpret_cast<VkPhysicalDeviceFeatures2*>(pFeats->pNext);
        }
    }
}

void GetPhysicalDeviceProperties2(VkPhysicalDevice physicalDevice,
                                  VkPhysicalDeviceProperties2* pProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceProperties2) {
        driver.GetPhysicalDeviceProperties2(physicalDevice, pProperties);
        return;
    }

    driver.GetPhysicalDeviceProperties2KHR(physicalDevice, pProperties);
}

void GetPhysicalDeviceFormatProperties2(
    VkPhysicalDevice physicalDevice,
    VkFormat format,
    VkFormatProperties2* pFormatProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceFormatProperties2) {
        driver.GetPhysicalDeviceFormatProperties2(physicalDevice, format,
                                                  pFormatProperties);
        return;
    }

    driver.GetPhysicalDeviceFormatProperties2KHR(physicalDevice, format,
                                                 pFormatProperties);
}

VkResult GetPhysicalDeviceImageFormatProperties2(
    VkPhysicalDevice physicalDevice,
    const VkPhysicalDeviceImageFormatInfo2* pImageFormatInfo,
    VkImageFormatProperties2* pImageFormatProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceImageFormatProperties2) {
        return driver.GetPhysicalDeviceImageFormatProperties2(
            physicalDevice, pImageFormatInfo, pImageFormatProperties);
    }

    return driver.GetPhysicalDeviceImageFormatProperties2KHR(
        physicalDevice, pImageFormatInfo, pImageFormatProperties);
}

void GetPhysicalDeviceQueueFamilyProperties2(
    VkPhysicalDevice physicalDevice,
    uint32_t* pQueueFamilyPropertyCount,
    VkQueueFamilyProperties2* pQueueFamilyProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceQueueFamilyProperties2) {
        driver.GetPhysicalDeviceQueueFamilyProperties2(
            physicalDevice, pQueueFamilyPropertyCount, pQueueFamilyProperties);
        return;
    }

    driver.GetPhysicalDeviceQueueFamilyProperties2KHR(
        physicalDevice, pQueueFamilyPropertyCount, pQueueFamilyProperties);
}

void GetPhysicalDeviceMemoryProperties2(
    VkPhysicalDevice physicalDevice,
    VkPhysicalDeviceMemoryProperties2* pMemoryProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceMemoryProperties2) {
        driver.GetPhysicalDeviceMemoryProperties2(physicalDevice,
                                                  pMemoryProperties);
        return;
    }

    driver.GetPhysicalDeviceMemoryProperties2KHR(physicalDevice,
                                                 pMemoryProperties);
}

void GetPhysicalDeviceSparseImageFormatProperties2(
    VkPhysicalDevice physicalDevice,
    const VkPhysicalDeviceSparseImageFormatInfo2* pFormatInfo,
    uint32_t* pPropertyCount,
    VkSparseImageFormatProperties2* pProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceSparseImageFormatProperties2) {
        driver.GetPhysicalDeviceSparseImageFormatProperties2(
            physicalDevice, pFormatInfo, pPropertyCount, pProperties);
        return;
    }

    driver.GetPhysicalDeviceSparseImageFormatProperties2KHR(
        physicalDevice, pFormatInfo, pPropertyCount, pProperties);
}

void GetPhysicalDeviceExternalBufferProperties(
    VkPhysicalDevice physicalDevice,
    const VkPhysicalDeviceExternalBufferInfo* pExternalBufferInfo,
    VkExternalBufferProperties* pExternalBufferProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceExternalBufferProperties) {
        driver.GetPhysicalDeviceExternalBufferProperties(
            physicalDevice, pExternalBufferInfo, pExternalBufferProperties);
        return;
    }

    if (driver.GetPhysicalDeviceExternalBufferPropertiesKHR) {
        driver.GetPhysicalDeviceExternalBufferPropertiesKHR(
            physicalDevice, pExternalBufferInfo, pExternalBufferProperties);
        return;
    }

    memset(&pExternalBufferProperties->externalMemoryProperties, 0,
           sizeof(VkExternalMemoryProperties));
}

void GetPhysicalDeviceExternalSemaphoreProperties(
    VkPhysicalDevice physicalDevice,
    const VkPhysicalDeviceExternalSemaphoreInfo* pExternalSemaphoreInfo,
    VkExternalSemaphoreProperties* pExternalSemaphoreProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceExternalSemaphoreProperties) {
        driver.GetPhysicalDeviceExternalSemaphoreProperties(
            physicalDevice, pExternalSemaphoreInfo,
            pExternalSemaphoreProperties);
        return;
    }

    if (driver.GetPhysicalDeviceExternalSemaphorePropertiesKHR) {
        driver.GetPhysicalDeviceExternalSemaphorePropertiesKHR(
            physicalDevice, pExternalSemaphoreInfo,
            pExternalSemaphoreProperties);
        return;
    }

    pExternalSemaphoreProperties->exportFromImportedHandleTypes = 0;
    pExternalSemaphoreProperties->compatibleHandleTypes = 0;
    pExternalSemaphoreProperties->externalSemaphoreFeatures = 0;
}

void GetPhysicalDeviceExternalFenceProperties(
    VkPhysicalDevice physicalDevice,
    const VkPhysicalDeviceExternalFenceInfo* pExternalFenceInfo,
    VkExternalFenceProperties* pExternalFenceProperties) {
    ATRACE_CALL();

    const auto& driver = GetData(physicalDevice).driver;

    if (driver.GetPhysicalDeviceExternalFenceProperties) {
        driver.GetPhysicalDeviceExternalFenceProperties(
            physicalDevice, pExternalFenceInfo, pExternalFenceProperties);
        return;
    }

    if (driver.GetPhysicalDeviceExternalFencePropertiesKHR) {
        driver.GetPhysicalDeviceExternalFencePropertiesKHR(
            physicalDevice, pExternalFenceInfo, pExternalFenceProperties);
        return;
    }

    pExternalFenceProperties->exportFromImportedHandleTypes = 0;
    pExternalFenceProperties->compatibleHandleTypes = 0;
    pExternalFenceProperties->externalFenceFeatures = 0;
}

}  // namespace driver
}  // namespace vulkan
