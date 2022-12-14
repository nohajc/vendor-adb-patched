#
# Copyright (C) 2015 The Android Open Source Project
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
#
LOCAL_PATH := $(call my-dir)

# simpleperf_script.zip (for release in ndk)
# ============================================================
SIMPLEPERF_SCRIPT_LIST := \
    app_api \
    doc \
    demo \
    runtest \
    scripts \
    testdata

SIMPLEPERF_SCRIPT_LIST := $(addprefix -D $(LOCAL_PATH)/,$(SIMPLEPERF_SCRIPT_LIST))

SIMPLEPERF_SCRIPT_PATH := \
    $(call intermediates-dir-for,PACKAGING,simplerperf_script,HOST)/simpleperf_script.zip

$(SIMPLEPERF_SCRIPT_PATH) : $(SOONG_ZIP)
	$(hide) $(SOONG_ZIP) -d -o $@ -C system/extras/simpleperf $(SIMPLEPERF_SCRIPT_LIST)

$(call dist-for-goals,simpleperf,$(SIMPLEPERF_SCRIPT_PATH):simpleperf/simpleperf_script.zip)
