/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SIMPLE_PERF_UTILS_H_
#define SIMPLE_PERF_UTILS_H_

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <fstream>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ziparchive/zip_archive.h>

namespace simpleperf {

static inline uint64_t AlignDown(uint64_t value, uint64_t alignment) {
  return value & ~(alignment - 1);
}

static inline uint64_t Align(uint64_t value, uint64_t alignment) {
  return AlignDown(value + alignment - 1, alignment);
}

#ifdef _WIN32
#define CLOSE_ON_EXEC_MODE ""
#define OS_PATH_SEPARATOR '\\'
#else
#define CLOSE_ON_EXEC_MODE "e"
#define OS_PATH_SEPARATOR '/'
#endif

// OneTimeAllocator is used to allocate memory many times and free only once at the end.
// It reduces the cost to free each allocated memory.
class OneTimeFreeAllocator {
 public:
  explicit OneTimeFreeAllocator(size_t unit_size = 8192u)
      : unit_size_(unit_size), cur_(nullptr), end_(nullptr) {}

  ~OneTimeFreeAllocator() { Clear(); }

  void Clear();
  const char* AllocateString(std::string_view s);

 private:
  const size_t unit_size_;
  std::vector<char*> v_;
  char* cur_;
  char* end_;
};

class LineReader {
 public:
  explicit LineReader(std::string_view file_path) : ifs_(file_path) {}
  // Return true if open file successfully.
  bool Ok() const { return ifs_.good(); }
  // If available, return next line content with new line, otherwise return nullptr.
  std::string* ReadLine() { return (std::getline(ifs_, buf_)) ? &buf_ : nullptr; }

 private:
  std::ifstream ifs_;
  std::string buf_;
};

class FileHelper {
 public:
  static android::base::unique_fd OpenReadOnly(const std::string& filename);
  static android::base::unique_fd OpenWriteOnly(const std::string& filename);
};

class ArchiveHelper {
 public:
  static std::unique_ptr<ArchiveHelper> CreateInstance(const std::string& filename);
  ~ArchiveHelper();
  // Iterate each entry in the zip file. Break the iteration when callback returns false.
  bool IterateEntries(const std::function<bool(ZipEntry&, const std::string&)>& callback);
  bool FindEntry(const std::string& name, ZipEntry* entry);
  bool GetEntryData(ZipEntry& entry, std::vector<uint8_t>* data);
  int GetFd();

 private:
  ArchiveHelper(ZipArchiveHandle handle, const std::string& filename)
      : handle_(handle), filename_(filename) {}

  ZipArchiveHandle handle_;
  std::string filename_;

  DISALLOW_COPY_AND_ASSIGN(ArchiveHelper);
};

template <class T>
void MoveFromBinaryFormat(T& data, const char*& p) {
  static_assert(std::is_standard_layout<T>::value, "not standard layout");
  memcpy(&data, p, sizeof(T));
  p += sizeof(T);
}

template <class T>
void MoveFromBinaryFormat(T& data, char*& p) {
  static_assert(std::is_standard_layout<T>::value, "not standard layout");
  memcpy(&data, p, sizeof(T));
  p += sizeof(T);
}

template <class T>
void MoveFromBinaryFormat(T* data_p, size_t n, const char*& p) {
  static_assert(std::is_standard_layout<T>::value, "not standard layout");
  size_t size = n * sizeof(T);
  memcpy(data_p, p, size);
  p += size;
}

template <class T>
void MoveToBinaryFormat(const T& data, char*& p) {
  static_assert(std::is_standard_layout<T>::value, "not standard layout");
  memcpy(p, &data, sizeof(T));
  p += sizeof(T);
}

template <class T>
void MoveToBinaryFormat(const T* data_p, size_t n, char*& p) {
  static_assert(std::is_standard_layout<T>::value, "not standard layout");
  size_t size = n * sizeof(T);
  memcpy(p, data_p, size);
  p += size;
}

void PrintIndented(size_t indent, const char* fmt, ...);
void FprintIndented(FILE* fp, size_t indent, const char* fmt, ...);

bool IsPowerOfTwo(uint64_t value);

std::vector<std::string> GetEntriesInDir(const std::string& dirpath);
std::vector<std::string> GetSubDirs(const std::string& dirpath);
bool IsDir(const std::string& dirpath);
bool IsRegularFile(const std::string& filename);
uint64_t GetFileSize(const std::string& filename);
bool MkdirWithParents(const std::string& path);

bool XzDecompress(const std::string& compressed_data, std::string* decompressed_data);

bool GetLogSeverity(const std::string& name, android::base::LogSeverity* severity);
std::string GetLogSeverityName();

bool IsRoot();

size_t GetPageSize();

uint64_t ConvertBytesToValue(const char* bytes, uint32_t size);

timeval SecondToTimeval(double time_in_sec);

std::string GetSimpleperfVersion();

std::optional<std::set<int>> GetCpusFromString(const std::string& s);
std::optional<std::set<pid_t>> GetTidsFromString(const std::string& s, bool check_if_exists);

template <typename T>
std::optional<std::set<T>> ParseUintVector(const std::string& s) {
  std::set<T> result;
  T value;
  for (const auto& p : android::base::Split(s, ",")) {
    if (!android::base::ParseUint(p.c_str(), &value, std::numeric_limits<T>::max())) {
      LOG(ERROR) << "Invalid Uint '" << p << "' in " << s;
      return std::nullopt;
    }
    result.insert(value);
  }
  return result;
}

// from boost::hash_combine
template <typename T>
static inline void HashCombine(size_t& seed, const T& val) {
  seed ^= std::hash<T>()(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

}  // namespace simpleperf

#endif  // SIMPLE_PERF_UTILS_H_
