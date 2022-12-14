/*
 * Copyright 2015 The Android Open Source Project
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
    // clang-format off
    {"vkCreateInstance", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateInstance>(CreateInstance))},
    {"vkEnumerateInstanceExtensionProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceExtensionProperties>(EnumerateInstanceExtensionProperties))},
    {"vkEnumerateInstanceLayerProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceLayerProperties>(EnumerateInstanceLayerProperties))},
    {"vkEnumerateInstanceVersion", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceVersion>(EnumerateInstanceVersion))},
    // clang-format on
};

const NameProc kInstanceProcs[] = {
    // clang-format off
    {"vkAcquireImageANDROID", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkAcquireImageANDROID>(AcquireImageANDROID))},
    {"vkAllocateCommandBuffers", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkAllocateCommandBuffers>(AllocateCommandBuffers))},
    {"vkAllocateDescriptorSets", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkAllocateDescriptorSets>(AllocateDescriptorSets))},
    {"vkAllocateMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkAllocateMemory>(AllocateMemory))},
    {"vkBeginCommandBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkBeginCommandBuffer>(BeginCommandBuffer))},
    {"vkBindBufferMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkBindBufferMemory>(BindBufferMemory))},
    {"vkBindBufferMemory2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkBindBufferMemory2>(BindBufferMemory2))},
    {"vkBindImageMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkBindImageMemory>(BindImageMemory))},
    {"vkBindImageMemory2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkBindImageMemory2>(BindImageMemory2))},
    {"vkCmdBeginQuery", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBeginQuery>(CmdBeginQuery))},
    {"vkCmdBeginRenderPass", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBeginRenderPass>(CmdBeginRenderPass))},
    {"vkCmdBeginRenderPass2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBeginRenderPass2>(CmdBeginRenderPass2))},
    {"vkCmdBeginRendering", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBeginRendering>(CmdBeginRendering))},
    {"vkCmdBindDescriptorSets", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBindDescriptorSets>(CmdBindDescriptorSets))},
    {"vkCmdBindIndexBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBindIndexBuffer>(CmdBindIndexBuffer))},
    {"vkCmdBindPipeline", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBindPipeline>(CmdBindPipeline))},
    {"vkCmdBindVertexBuffers", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBindVertexBuffers>(CmdBindVertexBuffers))},
    {"vkCmdBindVertexBuffers2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBindVertexBuffers2>(CmdBindVertexBuffers2))},
    {"vkCmdBlitImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBlitImage>(CmdBlitImage))},
    {"vkCmdBlitImage2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdBlitImage2>(CmdBlitImage2))},
    {"vkCmdClearAttachments", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdClearAttachments>(CmdClearAttachments))},
    {"vkCmdClearColorImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdClearColorImage>(CmdClearColorImage))},
    {"vkCmdClearDepthStencilImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdClearDepthStencilImage>(CmdClearDepthStencilImage))},
    {"vkCmdCopyBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyBuffer>(CmdCopyBuffer))},
    {"vkCmdCopyBuffer2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyBuffer2>(CmdCopyBuffer2))},
    {"vkCmdCopyBufferToImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyBufferToImage>(CmdCopyBufferToImage))},
    {"vkCmdCopyBufferToImage2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyBufferToImage2>(CmdCopyBufferToImage2))},
    {"vkCmdCopyImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyImage>(CmdCopyImage))},
    {"vkCmdCopyImage2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyImage2>(CmdCopyImage2))},
    {"vkCmdCopyImageToBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyImageToBuffer>(CmdCopyImageToBuffer))},
    {"vkCmdCopyImageToBuffer2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyImageToBuffer2>(CmdCopyImageToBuffer2))},
    {"vkCmdCopyQueryPoolResults", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdCopyQueryPoolResults>(CmdCopyQueryPoolResults))},
    {"vkCmdDispatch", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDispatch>(CmdDispatch))},
    {"vkCmdDispatchBase", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDispatchBase>(CmdDispatchBase))},
    {"vkCmdDispatchIndirect", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDispatchIndirect>(CmdDispatchIndirect))},
    {"vkCmdDraw", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDraw>(CmdDraw))},
    {"vkCmdDrawIndexed", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDrawIndexed>(CmdDrawIndexed))},
    {"vkCmdDrawIndexedIndirect", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDrawIndexedIndirect>(CmdDrawIndexedIndirect))},
    {"vkCmdDrawIndexedIndirectCount", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDrawIndexedIndirectCount>(CmdDrawIndexedIndirectCount))},
    {"vkCmdDrawIndirect", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDrawIndirect>(CmdDrawIndirect))},
    {"vkCmdDrawIndirectCount", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdDrawIndirectCount>(CmdDrawIndirectCount))},
    {"vkCmdEndQuery", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdEndQuery>(CmdEndQuery))},
    {"vkCmdEndRenderPass", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdEndRenderPass>(CmdEndRenderPass))},
    {"vkCmdEndRenderPass2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdEndRenderPass2>(CmdEndRenderPass2))},
    {"vkCmdEndRendering", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdEndRendering>(CmdEndRendering))},
    {"vkCmdExecuteCommands", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdExecuteCommands>(CmdExecuteCommands))},
    {"vkCmdFillBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdFillBuffer>(CmdFillBuffer))},
    {"vkCmdNextSubpass", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdNextSubpass>(CmdNextSubpass))},
    {"vkCmdNextSubpass2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdNextSubpass2>(CmdNextSubpass2))},
    {"vkCmdPipelineBarrier", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdPipelineBarrier>(CmdPipelineBarrier))},
    {"vkCmdPipelineBarrier2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdPipelineBarrier2>(CmdPipelineBarrier2))},
    {"vkCmdPushConstants", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdPushConstants>(CmdPushConstants))},
    {"vkCmdResetEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdResetEvent>(CmdResetEvent))},
    {"vkCmdResetEvent2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdResetEvent2>(CmdResetEvent2))},
    {"vkCmdResetQueryPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdResetQueryPool>(CmdResetQueryPool))},
    {"vkCmdResolveImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdResolveImage>(CmdResolveImage))},
    {"vkCmdResolveImage2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdResolveImage2>(CmdResolveImage2))},
    {"vkCmdSetBlendConstants", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetBlendConstants>(CmdSetBlendConstants))},
    {"vkCmdSetCullMode", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetCullMode>(CmdSetCullMode))},
    {"vkCmdSetDepthBias", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthBias>(CmdSetDepthBias))},
    {"vkCmdSetDepthBiasEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthBiasEnable>(CmdSetDepthBiasEnable))},
    {"vkCmdSetDepthBounds", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthBounds>(CmdSetDepthBounds))},
    {"vkCmdSetDepthBoundsTestEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthBoundsTestEnable>(CmdSetDepthBoundsTestEnable))},
    {"vkCmdSetDepthCompareOp", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthCompareOp>(CmdSetDepthCompareOp))},
    {"vkCmdSetDepthTestEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthTestEnable>(CmdSetDepthTestEnable))},
    {"vkCmdSetDepthWriteEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDepthWriteEnable>(CmdSetDepthWriteEnable))},
    {"vkCmdSetDeviceMask", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetDeviceMask>(CmdSetDeviceMask))},
    {"vkCmdSetEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetEvent>(CmdSetEvent))},
    {"vkCmdSetEvent2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetEvent2>(CmdSetEvent2))},
    {"vkCmdSetFrontFace", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetFrontFace>(CmdSetFrontFace))},
    {"vkCmdSetLineWidth", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetLineWidth>(CmdSetLineWidth))},
    {"vkCmdSetPrimitiveRestartEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetPrimitiveRestartEnable>(CmdSetPrimitiveRestartEnable))},
    {"vkCmdSetPrimitiveTopology", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetPrimitiveTopology>(CmdSetPrimitiveTopology))},
    {"vkCmdSetRasterizerDiscardEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetRasterizerDiscardEnable>(CmdSetRasterizerDiscardEnable))},
    {"vkCmdSetScissor", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetScissor>(CmdSetScissor))},
    {"vkCmdSetScissorWithCount", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetScissorWithCount>(CmdSetScissorWithCount))},
    {"vkCmdSetStencilCompareMask", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetStencilCompareMask>(CmdSetStencilCompareMask))},
    {"vkCmdSetStencilOp", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetStencilOp>(CmdSetStencilOp))},
    {"vkCmdSetStencilReference", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetStencilReference>(CmdSetStencilReference))},
    {"vkCmdSetStencilTestEnable", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetStencilTestEnable>(CmdSetStencilTestEnable))},
    {"vkCmdSetStencilWriteMask", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetStencilWriteMask>(CmdSetStencilWriteMask))},
    {"vkCmdSetViewport", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetViewport>(CmdSetViewport))},
    {"vkCmdSetViewportWithCount", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdSetViewportWithCount>(CmdSetViewportWithCount))},
    {"vkCmdUpdateBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdUpdateBuffer>(CmdUpdateBuffer))},
    {"vkCmdWaitEvents", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdWaitEvents>(CmdWaitEvents))},
    {"vkCmdWaitEvents2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdWaitEvents2>(CmdWaitEvents2))},
    {"vkCmdWriteTimestamp", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdWriteTimestamp>(CmdWriteTimestamp))},
    {"vkCmdWriteTimestamp2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCmdWriteTimestamp2>(CmdWriteTimestamp2))},
    {"vkCreateBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateBuffer>(CreateBuffer))},
    {"vkCreateBufferView", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateBufferView>(CreateBufferView))},
    {"vkCreateCommandPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateCommandPool>(CreateCommandPool))},
    {"vkCreateComputePipelines", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateComputePipelines>(CreateComputePipelines))},
    {"vkCreateDebugReportCallbackEXT", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateDebugReportCallbackEXT>(CreateDebugReportCallbackEXT))},
    {"vkCreateDescriptorPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateDescriptorPool>(CreateDescriptorPool))},
    {"vkCreateDescriptorSetLayout", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateDescriptorSetLayout>(CreateDescriptorSetLayout))},
    {"vkCreateDescriptorUpdateTemplate", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateDescriptorUpdateTemplate>(CreateDescriptorUpdateTemplate))},
    {"vkCreateDevice", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateDevice>(CreateDevice))},
    {"vkCreateEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateEvent>(CreateEvent))},
    {"vkCreateFence", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateFence>(CreateFence))},
    {"vkCreateFramebuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateFramebuffer>(CreateFramebuffer))},
    {"vkCreateGraphicsPipelines", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateGraphicsPipelines>(CreateGraphicsPipelines))},
    {"vkCreateImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateImage>(CreateImage))},
    {"vkCreateImageView", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateImageView>(CreateImageView))},
    {"vkCreateInstance", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateInstance>(CreateInstance))},
    {"vkCreatePipelineCache", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreatePipelineCache>(CreatePipelineCache))},
    {"vkCreatePipelineLayout", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreatePipelineLayout>(CreatePipelineLayout))},
    {"vkCreatePrivateDataSlot", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreatePrivateDataSlot>(CreatePrivateDataSlot))},
    {"vkCreateQueryPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateQueryPool>(CreateQueryPool))},
    {"vkCreateRenderPass", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateRenderPass>(CreateRenderPass))},
    {"vkCreateRenderPass2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateRenderPass2>(CreateRenderPass2))},
    {"vkCreateSampler", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateSampler>(CreateSampler))},
    {"vkCreateSamplerYcbcrConversion", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateSamplerYcbcrConversion>(CreateSamplerYcbcrConversion))},
    {"vkCreateSemaphore", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateSemaphore>(CreateSemaphore))},
    {"vkCreateShaderModule", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkCreateShaderModule>(CreateShaderModule))},
    {"vkDebugReportMessageEXT", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDebugReportMessageEXT>(DebugReportMessageEXT))},
    {"vkDestroyBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyBuffer>(DestroyBuffer))},
    {"vkDestroyBufferView", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyBufferView>(DestroyBufferView))},
    {"vkDestroyCommandPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyCommandPool>(DestroyCommandPool))},
    {"vkDestroyDebugReportCallbackEXT", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyDebugReportCallbackEXT>(DestroyDebugReportCallbackEXT))},
    {"vkDestroyDescriptorPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyDescriptorPool>(DestroyDescriptorPool))},
    {"vkDestroyDescriptorSetLayout", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyDescriptorSetLayout>(DestroyDescriptorSetLayout))},
    {"vkDestroyDescriptorUpdateTemplate", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyDescriptorUpdateTemplate>(DestroyDescriptorUpdateTemplate))},
    {"vkDestroyDevice", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyDevice>(DestroyDevice))},
    {"vkDestroyEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyEvent>(DestroyEvent))},
    {"vkDestroyFence", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyFence>(DestroyFence))},
    {"vkDestroyFramebuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyFramebuffer>(DestroyFramebuffer))},
    {"vkDestroyImage", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyImage>(DestroyImage))},
    {"vkDestroyImageView", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyImageView>(DestroyImageView))},
    {"vkDestroyInstance", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyInstance>(DestroyInstance))},
    {"vkDestroyPipeline", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyPipeline>(DestroyPipeline))},
    {"vkDestroyPipelineCache", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyPipelineCache>(DestroyPipelineCache))},
    {"vkDestroyPipelineLayout", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyPipelineLayout>(DestroyPipelineLayout))},
    {"vkDestroyPrivateDataSlot", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyPrivateDataSlot>(DestroyPrivateDataSlot))},
    {"vkDestroyQueryPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyQueryPool>(DestroyQueryPool))},
    {"vkDestroyRenderPass", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyRenderPass>(DestroyRenderPass))},
    {"vkDestroySampler", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroySampler>(DestroySampler))},
    {"vkDestroySamplerYcbcrConversion", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroySamplerYcbcrConversion>(DestroySamplerYcbcrConversion))},
    {"vkDestroySemaphore", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroySemaphore>(DestroySemaphore))},
    {"vkDestroyShaderModule", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDestroyShaderModule>(DestroyShaderModule))},
    {"vkDeviceWaitIdle", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkDeviceWaitIdle>(DeviceWaitIdle))},
    {"vkEndCommandBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEndCommandBuffer>(EndCommandBuffer))},
    {"vkEnumerateDeviceExtensionProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateDeviceExtensionProperties>(EnumerateDeviceExtensionProperties))},
    {"vkEnumerateDeviceLayerProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateDeviceLayerProperties>(EnumerateDeviceLayerProperties))},
    {"vkEnumerateInstanceExtensionProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceExtensionProperties>(EnumerateInstanceExtensionProperties))},
    {"vkEnumerateInstanceLayerProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceLayerProperties>(EnumerateInstanceLayerProperties))},
    {"vkEnumerateInstanceVersion", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumerateInstanceVersion>(EnumerateInstanceVersion))},
    {"vkEnumeratePhysicalDeviceGroups", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumeratePhysicalDeviceGroups>(EnumeratePhysicalDeviceGroups))},
    {"vkEnumeratePhysicalDevices", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkEnumeratePhysicalDevices>(EnumeratePhysicalDevices))},
    {"vkFlushMappedMemoryRanges", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkFlushMappedMemoryRanges>(FlushMappedMemoryRanges))},
    {"vkFreeCommandBuffers", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkFreeCommandBuffers>(FreeCommandBuffers))},
    {"vkFreeDescriptorSets", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkFreeDescriptorSets>(FreeDescriptorSets))},
    {"vkFreeMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkFreeMemory>(FreeMemory))},
    {"vkGetBufferDeviceAddress", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetBufferDeviceAddress>(GetBufferDeviceAddress))},
    {"vkGetBufferMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetBufferMemoryRequirements>(GetBufferMemoryRequirements))},
    {"vkGetBufferMemoryRequirements2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetBufferMemoryRequirements2>(GetBufferMemoryRequirements2))},
    {"vkGetBufferOpaqueCaptureAddress", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetBufferOpaqueCaptureAddress>(GetBufferOpaqueCaptureAddress))},
    {"vkGetDescriptorSetLayoutSupport", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDescriptorSetLayoutSupport>(GetDescriptorSetLayoutSupport))},
    {"vkGetDeviceBufferMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceBufferMemoryRequirements>(GetDeviceBufferMemoryRequirements))},
    {"vkGetDeviceGroupPeerMemoryFeatures", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceGroupPeerMemoryFeatures>(GetDeviceGroupPeerMemoryFeatures))},
    {"vkGetDeviceImageMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceImageMemoryRequirements>(GetDeviceImageMemoryRequirements))},
    {"vkGetDeviceImageSparseMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceImageSparseMemoryRequirements>(GetDeviceImageSparseMemoryRequirements))},
    {"vkGetDeviceMemoryCommitment", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceMemoryCommitment>(GetDeviceMemoryCommitment))},
    {"vkGetDeviceMemoryOpaqueCaptureAddress", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceMemoryOpaqueCaptureAddress>(GetDeviceMemoryOpaqueCaptureAddress))},
    {"vkGetDeviceProcAddr", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceProcAddr>(GetDeviceProcAddr))},
    {"vkGetDeviceQueue", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceQueue>(GetDeviceQueue))},
    {"vkGetDeviceQueue2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetDeviceQueue2>(GetDeviceQueue2))},
    {"vkGetEventStatus", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetEventStatus>(GetEventStatus))},
    {"vkGetFenceStatus", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetFenceStatus>(GetFenceStatus))},
    {"vkGetImageMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetImageMemoryRequirements>(GetImageMemoryRequirements))},
    {"vkGetImageMemoryRequirements2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetImageMemoryRequirements2>(GetImageMemoryRequirements2))},
    {"vkGetImageSparseMemoryRequirements", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetImageSparseMemoryRequirements>(GetImageSparseMemoryRequirements))},
    {"vkGetImageSparseMemoryRequirements2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetImageSparseMemoryRequirements2>(GetImageSparseMemoryRequirements2))},
    {"vkGetImageSubresourceLayout", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetImageSubresourceLayout>(GetImageSubresourceLayout))},
    {"vkGetInstanceProcAddr", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetInstanceProcAddr>(GetInstanceProcAddr))},
    {"vkGetPhysicalDeviceExternalBufferProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceExternalBufferProperties>(GetPhysicalDeviceExternalBufferProperties))},
    {"vkGetPhysicalDeviceExternalFenceProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceExternalFenceProperties>(GetPhysicalDeviceExternalFenceProperties))},
    {"vkGetPhysicalDeviceExternalSemaphoreProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceExternalSemaphoreProperties>(GetPhysicalDeviceExternalSemaphoreProperties))},
    {"vkGetPhysicalDeviceFeatures", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFeatures>(GetPhysicalDeviceFeatures))},
    {"vkGetPhysicalDeviceFeatures2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFeatures2>(GetPhysicalDeviceFeatures2))},
    {"vkGetPhysicalDeviceFeatures2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFeatures2KHR>(GetPhysicalDeviceFeatures2KHR))},
    {"vkGetPhysicalDeviceFormatProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFormatProperties>(GetPhysicalDeviceFormatProperties))},
    {"vkGetPhysicalDeviceFormatProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFormatProperties2>(GetPhysicalDeviceFormatProperties2))},
    {"vkGetPhysicalDeviceFormatProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceFormatProperties2KHR>(GetPhysicalDeviceFormatProperties2KHR))},
    {"vkGetPhysicalDeviceImageFormatProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceImageFormatProperties>(GetPhysicalDeviceImageFormatProperties))},
    {"vkGetPhysicalDeviceImageFormatProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceImageFormatProperties2>(GetPhysicalDeviceImageFormatProperties2))},
    {"vkGetPhysicalDeviceImageFormatProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceImageFormatProperties2KHR>(GetPhysicalDeviceImageFormatProperties2KHR))},
    {"vkGetPhysicalDeviceMemoryProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(GetPhysicalDeviceMemoryProperties))},
    {"vkGetPhysicalDeviceMemoryProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceMemoryProperties2>(GetPhysicalDeviceMemoryProperties2))},
    {"vkGetPhysicalDeviceMemoryProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceMemoryProperties2KHR>(GetPhysicalDeviceMemoryProperties2KHR))},
    {"vkGetPhysicalDeviceProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceProperties>(GetPhysicalDeviceProperties))},
    {"vkGetPhysicalDeviceProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceProperties2>(GetPhysicalDeviceProperties2))},
    {"vkGetPhysicalDeviceProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceProperties2KHR>(GetPhysicalDeviceProperties2KHR))},
    {"vkGetPhysicalDeviceQueueFamilyProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceQueueFamilyProperties>(GetPhysicalDeviceQueueFamilyProperties))},
    {"vkGetPhysicalDeviceQueueFamilyProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceQueueFamilyProperties2>(GetPhysicalDeviceQueueFamilyProperties2))},
    {"vkGetPhysicalDeviceQueueFamilyProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceQueueFamilyProperties2KHR>(GetPhysicalDeviceQueueFamilyProperties2KHR))},
    {"vkGetPhysicalDeviceSparseImageFormatProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceSparseImageFormatProperties>(GetPhysicalDeviceSparseImageFormatProperties))},
    {"vkGetPhysicalDeviceSparseImageFormatProperties2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceSparseImageFormatProperties2>(GetPhysicalDeviceSparseImageFormatProperties2))},
    {"vkGetPhysicalDeviceSparseImageFormatProperties2KHR", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceSparseImageFormatProperties2KHR>(GetPhysicalDeviceSparseImageFormatProperties2KHR))},
    {"vkGetPhysicalDeviceToolProperties", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPhysicalDeviceToolProperties>(GetPhysicalDeviceToolProperties))},
    {"vkGetPipelineCacheData", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPipelineCacheData>(GetPipelineCacheData))},
    {"vkGetPrivateData", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetPrivateData>(GetPrivateData))},
    {"vkGetQueryPoolResults", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetQueryPoolResults>(GetQueryPoolResults))},
    {"vkGetRenderAreaGranularity", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetRenderAreaGranularity>(GetRenderAreaGranularity))},
    {"vkGetSemaphoreCounterValue", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetSemaphoreCounterValue>(GetSemaphoreCounterValue))},
    {"vkGetSwapchainGrallocUsage2ANDROID", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetSwapchainGrallocUsage2ANDROID>(GetSwapchainGrallocUsage2ANDROID))},
    {"vkGetSwapchainGrallocUsage3ANDROID", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetSwapchainGrallocUsage3ANDROID>(GetSwapchainGrallocUsage3ANDROID))},
    {"vkGetSwapchainGrallocUsageANDROID", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkGetSwapchainGrallocUsageANDROID>(GetSwapchainGrallocUsageANDROID))},
    {"vkInvalidateMappedMemoryRanges", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkInvalidateMappedMemoryRanges>(InvalidateMappedMemoryRanges))},
    {"vkMapMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkMapMemory>(MapMemory))},
    {"vkMergePipelineCaches", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkMergePipelineCaches>(MergePipelineCaches))},
    {"vkQueueBindSparse", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkQueueBindSparse>(QueueBindSparse))},
    {"vkQueueSignalReleaseImageANDROID", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkQueueSignalReleaseImageANDROID>(QueueSignalReleaseImageANDROID))},
    {"vkQueueSubmit", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkQueueSubmit>(QueueSubmit))},
    {"vkQueueSubmit2", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkQueueSubmit2>(QueueSubmit2))},
    {"vkQueueWaitIdle", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkQueueWaitIdle>(QueueWaitIdle))},
    {"vkResetCommandBuffer", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetCommandBuffer>(ResetCommandBuffer))},
    {"vkResetCommandPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetCommandPool>(ResetCommandPool))},
    {"vkResetDescriptorPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetDescriptorPool>(ResetDescriptorPool))},
    {"vkResetEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetEvent>(ResetEvent))},
    {"vkResetFences", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetFences>(ResetFences))},
    {"vkResetQueryPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkResetQueryPool>(ResetQueryPool))},
    {"vkSetEvent", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkSetEvent>(SetEvent))},
    {"vkSetPrivateData", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkSetPrivateData>(SetPrivateData))},
    {"vkSignalSemaphore", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkSignalSemaphore>(SignalSemaphore))},
    {"vkTrimCommandPool", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkTrimCommandPool>(TrimCommandPool))},
    {"vkUnmapMemory", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkUnmapMemory>(UnmapMemory))},
    {"vkUpdateDescriptorSetWithTemplate", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkUpdateDescriptorSetWithTemplate>(UpdateDescriptorSetWithTemplate))},
    {"vkUpdateDescriptorSets", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkUpdateDescriptorSets>(UpdateDescriptorSets))},
    {"vkWaitForFences", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkWaitForFences>(WaitForFences))},
    {"vkWaitSemaphores", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_vkWaitSemaphores>(WaitSemaphores))},
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

}  // namespace null_driver
