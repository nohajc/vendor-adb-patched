/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <stdio.h>

#include "command.h"
#include "get_test_data.h"
#include "record_file.h"
#include "test_util.h"
#include "utils.h"

using namespace simpleperf;

#if defined(__ANDROID__)

static bool WaitUntilAppExit(const std::string& package_name) {
  while (true) {
    std::unique_ptr<FILE, decltype(&pclose)> fp(popen("ps -e", "re"), pclose);
    if (!fp) {
      return false;
    }
    std::string s;
    if (!android::base::ReadFdToString(fileno(fp.get()), &s)) {
      return false;
    }
    if (s.find(package_name) == std::string::npos) {
      break;
    }
    sleep(1);
  }
  return true;
}

static void CheckPerfDataFile(const std::string& filename) {
  auto reader = RecordFileReader::CreateInstance(filename);
  ASSERT_TRUE(reader);
  bool has_sample = false;
  ASSERT_TRUE(reader->ReadDataSection([&](std::unique_ptr<Record> r) {
    if (r->type() == PERF_RECORD_SAMPLE) {
      has_sample = true;
    }
    return true;
  }));
  ASSERT_TRUE(has_sample);
}

static void RecordApp(const std::string& package_name, const std::string& apk_path) {
  // 1. Prepare recording.
  ASSERT_TRUE(CreateCommandInstance("api-prepare")->Run({}));

  // 2. Install apk and start the app.
  AppHelper app_helper;
  ASSERT_TRUE(app_helper.InstallApk(apk_path, package_name));
  ASSERT_TRUE(app_helper.StartApp("am start " + package_name + "/.MainActivity"));

  // 3. Wait until the app stops.
  sleep(3);
  ASSERT_TRUE(WaitUntilAppExit(package_name));

  // 4. Collect perf.data.
  SetRunInAppToolForTesting(true, true);
  TemporaryFile tmpfile;
  ASSERT_TRUE(
      CreateCommandInstance("api-collect")->Run({"--app", package_name, "-o", tmpfile.path}));

  // 5. Verify perf.data.
  TemporaryDir tmpdir;
  ASSERT_TRUE(Workload::RunCmd({"unzip", "-d", tmpdir.path, tmpfile.path}));
  for (const std::string& filename : GetEntriesInDir(tmpdir.path)) {
    CheckPerfDataFile(std::string(tmpdir.path) + "/" + filename);
  }
}

#endif  // defined(__ANDROID__)

TEST(cmd_api, java_app) {
#if defined(__ANDROID__)
  RecordApp("simpleperf.demo.java_api", GetTestData("java_api.apk"));
#else
  GTEST_LOG_(INFO) << "This test tests recording apps on Android.";
#endif
}

TEST(cmd_api, native_app) {
#if defined(__ANDROID__)
  RecordApp("simpleperf.demo.cpp_api", GetTestData("cpp_api.apk"));
#else
  GTEST_LOG_(INFO) << "This test tests recording apps on Android.";
#endif
}