/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <string>

#include "Alloc.h"
#include "Pointers.h"
#include "Utils.h"

void AllocGetData(const std::string& line, AllocEntry* entry) {
  int line_pos = 0;
  char name[128];
  // All lines have this format:
  //   TID: ALLOCATION_TYPE POINTER
  // where
  //   TID is the thread id of the thread doing the operation.
  //   ALLOCATION_TYPE is one of malloc, calloc, memalign, realloc, free, thread_done
  //   POINTER is the hex value of the actual pointer
  if (sscanf(line.c_str(), "%d: %127s %" SCNx64 " %n", &entry->tid, name, &entry->ptr, &line_pos) !=
      3) {
    errx(1, "File Error: Failed to process %s", line.c_str());
  }
  const char* line_end = &line[line_pos];
  std::string type(name);
  if (type == "malloc") {
    // Format:
    //   TID: malloc POINTER SIZE_OF_ALLOCATION
    if (sscanf(line_end, "%zu", &entry->size) != 1) {
      errx(1, "File Error: Failed to read malloc data %s", line.c_str());
    }
    entry->type = MALLOC;
  } else if (type == "free") {
    // Format:
    //   TID: free POINTER
    entry->type = FREE;
  } else if (type == "calloc") {
    // Format:
    //   TID: calloc POINTER ITEM_COUNT ITEM_SIZE
    if (sscanf(line_end, "%" SCNd64 " %zu", &entry->u.n_elements, &entry->size) != 2) {
      errx(1, "File Error: Failed to read calloc data %s", line.c_str());
    }
    entry->type = CALLOC;
  } else if (type == "realloc") {
    // Format:
    //   TID: calloc POINTER NEW_SIZE OLD_POINTER
    if (sscanf(line_end, "%" SCNx64 " %zu", &entry->u.old_ptr, &entry->size) != 2) {
      errx(1, "File Error: Failed to read realloc data %s", line.c_str());
    }
    entry->type = REALLOC;
  } else if (type == "memalign") {
    // Format:
    //   TID: memalign POINTER ALIGNMENT SIZE
    if (sscanf(line_end, "%" SCNd64 " %zu", &entry->u.align, &entry->size) != 2) {
      errx(1, "File Error: Failed to read memalign data %s", line.c_str());
    }
    entry->type = MEMALIGN;
  } else if (type == "thread_done") {
    entry->type = THREAD_DONE;
  } else {
    errx(1, "File Error: Unknown type %s", type.c_str());
  }
}

bool AllocDoesFree(const AllocEntry& entry) {
  switch (entry.type) {
    case MALLOC:
    case CALLOC:
    case MEMALIGN:
    case THREAD_DONE:
      return false;

    case FREE:
      return entry.ptr != 0;

    case REALLOC:
      return entry.u.old_ptr != 0;
  }
}

static uint64_t MallocExecute(const AllocEntry& entry, Pointers* pointers) {
  int pagesize = getpagesize();
  uint64_t time_nsecs = Nanotime();
  void* memory = malloc(entry.size);
  MakeAllocationResident(memory, entry.size, pagesize);
  time_nsecs = Nanotime() - time_nsecs;

  pointers->Add(entry.ptr, memory);

  return time_nsecs;
}

static uint64_t CallocExecute(const AllocEntry& entry, Pointers* pointers) {
  int pagesize = getpagesize();
  uint64_t time_nsecs = Nanotime();
  void* memory = calloc(entry.u.n_elements, entry.size);
  MakeAllocationResident(memory, entry.u.n_elements * entry.size, pagesize);
  time_nsecs = Nanotime() - time_nsecs;

  pointers->Add(entry.ptr, memory);

  return time_nsecs;
}

static uint64_t ReallocExecute(const AllocEntry& entry, Pointers* pointers) {
  void* old_memory = nullptr;
  if (entry.u.old_ptr != 0) {
    old_memory = pointers->Remove(entry.u.old_ptr);
  }

  int pagesize = getpagesize();
  uint64_t time_nsecs = Nanotime();
  void* memory = realloc(old_memory, entry.size);
  MakeAllocationResident(memory, entry.size, pagesize);
  time_nsecs = Nanotime() - time_nsecs;

  pointers->Add(entry.ptr, memory);

  return time_nsecs;
}

static uint64_t MemalignExecute(const AllocEntry& entry, Pointers* pointers) {
  int pagesize = getpagesize();
  uint64_t time_nsecs = Nanotime();
  void* memory = memalign(entry.u.align, entry.size);
  MakeAllocationResident(memory, entry.size, pagesize);
  time_nsecs = Nanotime() - time_nsecs;

  pointers->Add(entry.ptr, memory);

  return time_nsecs;
}

static uint64_t FreeExecute(const AllocEntry& entry, Pointers* pointers) {
  if (entry.ptr == 0) {
    return 0;
  }

  void* memory = pointers->Remove(entry.ptr);
  uint64_t time_nsecs = Nanotime();
  free(memory);
  return Nanotime() - time_nsecs;
}

uint64_t AllocExecute(const AllocEntry& entry, Pointers* pointers) {
  switch (entry.type) {
    case MALLOC:
      return MallocExecute(entry, pointers);
    case CALLOC:
      return CallocExecute(entry, pointers);
    case REALLOC:
      return ReallocExecute(entry, pointers);
    case MEMALIGN:
      return MemalignExecute(entry, pointers);
    case FREE:
      return FreeExecute(entry, pointers);
    default:
      return 0;
  }
}
