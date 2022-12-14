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

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <bootloader_message/bootloader_message.h>

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " none|memtag|memtag-once|memtag-kernel|memtag-kernel-once[,.."
                     ".] [default|force_on|force_off]\n";
        return 1;
    }
  std::string value = argv[1];
  misc_memtag_message m = {.version = MISC_MEMTAG_MESSAGE_VERSION,
                           .magic = MISC_MEMTAG_MAGIC_HEADER};
  bool valid_value = true;
  for (const auto& field : android::base::Split(value, ",")) {
    if (field == "memtag") {
      m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG;
    } else if (field == "memtag-once") {
      m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG_ONCE;
    } else if (field == "memtag-kernel") {
      m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG_KERNEL;
    } else if (field == "memtag-kernel-once") {
      m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG_KERNEL_ONCE;
    } else if (field == "memtag-off") {
      m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG_OFF;
    } else if (field != "none") {
      LOG(ERROR) << "Unknown value for mode: " << field;
      valid_value = false;
      m = {.version = MISC_MEMTAG_MESSAGE_VERSION, .magic = MISC_MEMTAG_MAGIC_HEADER};
      break;
    }
  }
  bool valid_override = true;
  std::string override_value;
  if (argc == 3) {
    override_value = argv[2];
  }
  if (override_value == "force_off") {
    // If the force_off override is active, only allow MEMTAG_MODE_MEMTAG_ONCE.
    m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG_OFF;
    m.memtag_mode &= ~MISC_MEMTAG_MODE_MEMTAG;
  } else if (override_value == "force_on") {
    m.memtag_mode |= MISC_MEMTAG_MODE_MEMTAG;
    m.memtag_mode &= ~MISC_MEMTAG_MODE_MEMTAG_OFF;
  } else if (!override_value.empty() && override_value != "default") {
    LOG(ERROR) << "Unknown value for override: " << override_value;
    valid_override = false;
  }
  if (!valid_value && !valid_override) {
    return 1;
  }
  std::string err;
  if (!WriteMiscMemtagMessage(m, &err)) {
    LOG(ERROR) << "Failed to apply mode: " << value << ", override: " << override_value << err;
    return 1;
  } else {
    const char* parse_error = "";
    const char* verb = "Applied";
    if (!valid_value) {
      parse_error = " (invalid mode)";
      verb = "Partially applied";
    } else if (!valid_override) {
      // else if because we bail out if both are false above.
      parse_error = " (invalid override)";
      verb = "Partially applied";
    }
    LOG(INFO) << verb << " mode: " << value << ", "
              << "override: " << override_value << parse_error;
    return !valid_value || !valid_override;
  }
}
