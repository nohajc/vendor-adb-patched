/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef _UI_INPUT_DISPATCHER_DEBUG_CONFIG_H
#define _UI_INPUT_DISPATCHER_DEBUG_CONFIG_H

#define LOG_TAG "InputDispatcher"

#include <log/log.h>
#include <log/log_event_list.h>

namespace android::inputdispatcher {
/**
 * Log detailed debug messages about each inbound event notification to the dispatcher.
 * Enable this via "adb shell setprop log.tag.InputDispatcherInboundEvent DEBUG" (requires restart)
 */
const bool DEBUG_INBOUND_EVENT_DETAILS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "InboundEvent", ANDROID_LOG_INFO);

/**
 * Log detailed debug messages about each outbound event processed by the dispatcher.
 * Enable this via "adb shell setprop log.tag.InputDispatcherOutboundEvent DEBUG" (requires restart)
 */
const bool DEBUG_OUTBOUND_EVENT_DETAILS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "OutboundEvent", ANDROID_LOG_INFO);

/**
 * Log debug messages about the dispatch cycle.
 * Enable this via "adb shell setprop log.tag.InputDispatcherDispatchCycle DEBUG" (requires restart)
 */
const bool DEBUG_DISPATCH_CYCLE =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "DispatchCycle", ANDROID_LOG_INFO);

/**
 * Log debug messages about channel creation
 * Enable this via "adb shell setprop log.tag.InputDispatcherChannelCreation DEBUG" (requires
 * restart)
 */
const bool DEBUG_CHANNEL_CREATION =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "ChannelCreation", ANDROID_LOG_INFO);

/**
 * Log debug messages about input event injection.
 * Enable this via "adb shell setprop log.tag.InputDispatcherInjection DEBUG" (requires restart)
 */
const bool DEBUG_INJECTION =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Injection", ANDROID_LOG_INFO);

/**
 * Log debug messages about input focus tracking.
 * Enable this via "adb shell setprop log.tag.InputDispatcherFocus DEBUG" (requires restart)
 */
const bool DEBUG_FOCUS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Focus", ANDROID_LOG_INFO);

/**
 * Log debug messages about touch mode event
 * Enable this via "adb shell setprop log.tag.InputDispatcherTouchMode DEBUG" (requires restart)
 */
const bool DEBUG_TOUCH_MODE =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "TouchMode", ANDROID_LOG_INFO);

/**
 * Log debug messages about touch occlusion
 */
constexpr bool DEBUG_TOUCH_OCCLUSION = true;

/**
 * Log debug messages about the app switch latency optimization.
 * Enable this via "adb shell setprop log.tag.InputDispatcherAppSwitch DEBUG" (requires restart)
 */
const bool DEBUG_APP_SWITCH =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "AppSwitch", ANDROID_LOG_INFO);

/**
 * Log debug messages about hover events.
 * Enable this via "adb shell setprop log.tag.InputDispatcherHover DEBUG" (requires restart)
 */
const bool DEBUG_HOVER =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Hover", ANDROID_LOG_INFO);
} // namespace android::inputdispatcher

#endif // _UI_INPUT_DISPATCHER_DEBUG_CONFIG_H