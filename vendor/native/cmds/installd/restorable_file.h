/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_INSTALLD_RESTORABLE_FILE_H
#define ANDROID_INSTALLD_RESTORABLE_FILE_H

#include <functional>
#include <string>

#include "unique_file.h"

namespace android {
namespace installd {

// This is a file abstraction which allows restoring to the original file while temporary work
// file is updated.
//
// Typical flow for this API will be:
// RestorableFile rf =  RestorableFile::CreateWritableFile(...)
// write to file using file descriptor acquired from: rf.fd()
// Make work file into a regular file with: rf.CommitWorkFile()
// Or throw away the work file by destroying the instance without calling CommitWorkFile().
// The temporary work file is closed / removed when an instance is destroyed without calling
// CommitWorkFile(). The original file, if CommitWorkFile() is not called, will be kept.
//
// For safer restoration of original file when commit fails, following 3 steps can be taken:
// 1. CreateBackupFile(): This renames an existing regular file into a separate backup file.
// 2. CommitWorkFile(): Rename the work file into the regular file.
// 3. RemoveBackupFile(): Removes the backup file
// If CommitWorkFile fails, client can call RestoreBackupFile() which will restore regular file from
// the backup.
class RestorableFile {
public:
    // Creates invalid instance with no fd (=-1) and empty path.
    RestorableFile();
    RestorableFile(RestorableFile&& other) = default;
    ~RestorableFile();

    // Passes all contents of other file into the current file.
    // Files kept for the current file will be either deleted or committed depending on
    // CommitWorkFile() and DisableCleanUp() calls made before this.
    RestorableFile& operator=(RestorableFile&& other) = default;

    // Gets file descriptor for backing work (=temporary) file. If work file does not exist, it will
    // return -1.
    int fd() const { return unique_file_.fd(); }

    // Gets the path name for the regular file (not temporary file).
    const std::string& path() const { return unique_file_.path(); }

    // Closes work file, deletes it and resets all internal states into default states.
    void reset();

    // Closes work file and closes all files including work file, backup file and regular file.
    void ResetAndRemoveAllFiles();

    // Creates a backup file by renaming existing regular file. This will return false if renaming
    // fails. If regular file for renaming does not exist, it will return true.
    bool CreateBackupFile();

    // Closes existing work file and makes it a regular file.
    // Note that the work file is closed and fd() will return -1 after this. path() will still
    // return the original path.
    // This will return false when committing fails (=cannot rename). Both the regular file and tmp
    // file will be deleted when it fails.
    bool CommitWorkFile();

    // Cancels the commit and restores the backup file into the regular one. If renaming fails,
    // it will return false. This returns true if the backup file does not exist.
    bool RestoreBackupFile();

    // Removes the backup file.
    void RemoveBackupFile();

    // Gets UniqueFile with the same path and fd() pointing to the work file.
    const UniqueFile& GetUniqueFile() const;

    // Creates writable RestorableFile. This involves creating tmp file for writing.
    static RestorableFile CreateWritableFile(const std::string& path, int permissions);

    // Removes the specified file together with tmp file generated as RestorableFile.
    static void RemoveAllFiles(const std::string& path);

private:
    RestorableFile(int value, const std::string& path);

    // Used as a storage for work file fd and path string.
    UniqueFile unique_file_;
};

} // namespace installd
} // namespace android

#endif // ANDROID_INSTALLD_RESTORABLE_FILE_H
