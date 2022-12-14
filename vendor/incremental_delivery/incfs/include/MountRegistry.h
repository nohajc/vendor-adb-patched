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

#pragma once

#include <android-base/unique_fd.h>

#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace android::incfs {

//
// MountRegistry - a collection of mount points for a particular filesystem, with
//      live tracking of binds, mounts and unmounts on it
//

class MountRegistry final {
public:
    // std::less<> enables heterogeneous lookups, e.g. by a string_view
    using BindMap = std::map<std::string, std::pair<std::string, int>, std::less<>>;

    class Mounts final {
        struct Root {
            std::string path;
            std::string backing;
            std::vector<BindMap::const_iterator> binds;

            bool empty() const { return path.empty(); }
            void clear() {
                decltype(path)().swap(path);
                decltype(binds)().swap(binds);
            }
        };

    public:
        struct Mount final {
            Mount(std::vector<Root>::const_iterator base) : mBase(base) {}

            std::string_view root() const { return mBase->path; }
            std::string_view backingDir() const { return mBase->backing; }
            std::vector<std::pair<std::string_view, std::string_view>> binds() const;

        private:
            std::vector<Root>::const_iterator mBase;
        };

        struct iterator final : public std::vector<Root>::const_iterator {
            using base = std::vector<Root>::const_iterator;
            using value_type = Mount;
            value_type operator*() const { return Mount(*this); }

            explicit iterator(base b) : base(b) {}
        };

        static Mounts load(base::borrowed_fd fd, std::string_view filesystem);
        bool loadFrom(base::borrowed_fd fd, std::string_view filesystem);

        iterator begin() const { return iterator(roots.begin()); }
        iterator end() const { return iterator(roots.end()); }
        size_t size() const { return roots.size(); }
        bool empty() const { return roots.empty(); }

        std::string_view rootFor(std::string_view path) const;
        std::pair<std::string_view, std::string> rootAndSubpathFor(std::string_view path) const;

        void swap(Mounts& other);
        void clear();

        void addRoot(std::string_view root, std::string_view backingDir);
        void removeRoot(std::string_view root);
        void addBind(std::string_view what, std::string_view where);
        void moveBind(std::string_view src, std::string_view dest);
        void removeBind(std::string_view what);

    private:
        std::pair<int, BindMap::const_iterator> rootIndex(std::string_view path) const;

        std::vector<Root> roots;
        BindMap rootByBindPoint;
    };

    MountRegistry(std::string_view filesystem = {});
    ~MountRegistry();

    std::string rootFor(std::string_view path);
    std::pair<std::string, std::string> rootAndSubpathFor(std::string_view path);
    Mounts copyMounts();

    void reload();

private:
    [[nodiscard]] std::unique_lock<std::mutex> ensureUpToDate();

private:
    const std::string mFilesystem;
    base::unique_fd mMountInfo;
    Mounts mMounts;
    mutable std::mutex mDataMutex;
};

} // namespace android::incfs
