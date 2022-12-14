#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include <string>

extern "C" {
    DIR *termuxadb_opendir(const char *name);
    int termuxadb_closedir(DIR *dirp);

    int termuxadb_open(std::string_view path, int options);
    int termuxadb_create(std::string_view path, int options, int mode);

    int termuxadb_close(int fd);
}

namespace termuxadb {
    static inline DIR *opendir(const char *name) {
        return termuxadb_opendir(name);
    }

    static inline int closedir(DIR *dirp) {
        return termuxadb_closedir(dirp);
    }

    static inline struct dirent *readdir(DIR *dirp) {
        return ::readdir(dirp);
    }

    static inline int unix_open(std::string_view path, int options, ...) {
        std::string zero_terminated(path.begin(), path.end());
        if ((options & O_CREAT) == 0) {
            return TEMP_FAILURE_RETRY(termuxadb_open(zero_terminated.c_str(), options));
        } else {
            int mode;
            va_list args;
            va_start(args, options);
            mode = va_arg(args, int);
            va_end(args);
            return TEMP_FAILURE_RETRY(termuxadb_create(zero_terminated.c_str(), options, mode));
        }
    }

    static inline int adb_close(int fd) {
        return termuxadb_close(fd);
    }
}
