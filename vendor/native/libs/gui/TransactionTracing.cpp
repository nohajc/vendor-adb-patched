/*
 * Copyright 2020 The Android Open Source Project
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

#include "gui/TransactionTracing.h"
#include "gui/ISurfaceComposer.h"

#include <private/gui/ComposerService.h>

namespace android {

sp<TransactionTraceListener> TransactionTraceListener::sInstance = nullptr;
std::mutex TransactionTraceListener::sMutex;

TransactionTraceListener::TransactionTraceListener() {}

sp<TransactionTraceListener> TransactionTraceListener::getInstance() {
    const std::lock_guard<std::mutex> lock(sMutex);

    if (sInstance == nullptr) {
        sInstance = new TransactionTraceListener;

        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        sf->addTransactionTraceListener(sInstance);
    }

    return sInstance;
}

binder::Status TransactionTraceListener::onToggled(bool enabled) {
    ALOGD("TransactionTraceListener: onToggled listener called");
    mTracingEnabled = enabled;

    return binder::Status::ok();
}

bool TransactionTraceListener::isTracingEnabled() {
    return mTracingEnabled;
}

} // namespace android