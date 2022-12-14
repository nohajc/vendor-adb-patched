# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

#
# -- All host/targets excluding windows
#

include $(CLEAR_VARS)
LOCAL_MODULE := mke2fs.conf
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
include $(BUILD_PREBUILT)
