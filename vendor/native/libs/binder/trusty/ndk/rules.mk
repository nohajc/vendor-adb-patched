# Copyright (C) 2021 The Android Open Source Project
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

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

LIBBINDER_NDK_DIR := frameworks/native/libs/binder/ndk

MODULE_SRCS := \
	$(LIBBINDER_NDK_DIR)/ibinder.cpp \
	$(LIBBINDER_NDK_DIR)/libbinder.cpp \
	$(LIBBINDER_NDK_DIR)/parcel.cpp \
	$(LIBBINDER_NDK_DIR)/status.cpp \

MODULE_EXPORT_INCLUDES += \
	$(LOCAL_DIR)/include \
	$(LIBBINDER_NDK_DIR)/include_cpp \
	$(LIBBINDER_NDK_DIR)/include_ndk \
	$(LIBBINDER_NDK_DIR)/include_platform \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libstdc++-trusty \
	frameworks/native/libs/binder/trusty \

include make/library.mk
