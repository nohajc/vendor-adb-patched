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
#include "dump.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/sha.h>
#include <selinux/android.h>
#include <selinux/selinux.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "linux/incrementalfs.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string_view>

using namespace std::literals;

namespace {

// stuff from the internal incfs implementation

#ifndef __packed
#define __packed __attribute__((packed))
#endif

struct mem_range {
    char* data;
    size_t len;
};

#define INCFS_MAX_NAME_LEN 255
#define INCFS_FORMAT_V1 1
#define INCFS_FORMAT_CURRENT_VER INCFS_FORMAT_V1

enum incfs_metadata_type {
    INCFS_MD_NONE = 0,
    INCFS_MD_BLOCK_MAP = 1,
    INCFS_MD_FILE_ATTR = 2,
    INCFS_MD_SIGNATURE = 3,
    INCFS_MD_STATUS = 4,
    INCFS_MD_VERITY_SIGNATURE = 5,
};

enum incfs_file_header_flags {
    INCFS_FILE_MAPPED = 1 << 1,
};

/* Header included at the beginning of all metadata records on the disk. */
struct incfs_md_header {
    uint8_t h_md_entry_type;

    /*
     * Size of the metadata record.
     * (e.g. inode, dir entry etc) not just this struct.
     */
    int16_t h_record_size;

    /*
     * CRC32 of the metadata record.
     * (e.g. inode, dir entry etc) not just this struct.
     */
    int32_t h_unused1;

    /* Offset of the next metadata entry if any */
    int64_t h_next_md_offset;

    /* Offset of the previous metadata entry if any */
    int64_t h_unused2;

} __packed;

/* Backing file header */
struct incfs_file_header {
    /* Magic number: INCFS_MAGIC_NUMBER */
    __le64 fh_magic;

    /* Format version: INCFS_FORMAT_CURRENT_VER */
    __le64 fh_version;

    /* sizeof(incfs_file_header) */
    __le16 fh_header_size;

    /* INCFS_DATA_FILE_BLOCK_SIZE */
    __le16 fh_data_block_size;

    /* File flags, from incfs_file_header_flags */
    __le32 fh_flags;

    union {
        /* Standard incfs file */
        struct {
            /* Offset of the first metadata record */
            __le64 fh_first_md_offset;

            /* Full size of the file's content */
            __le64 fh_file_size;

            /* File uuid */
            incfs_uuid_t fh_uuid;
        };

        /* Mapped file - INCFS_FILE_MAPPED set in fh_flags */
        struct {
            /* Offset in original file */
            __le64 fh_original_offset;

            /* Full size of the file's content */
            __le64 fh_mapped_file_size;

            /* Original file's uuid */
            incfs_uuid_t fh_original_uuid;
        };
    };
} __packed;

enum incfs_block_map_entry_flags {
    INCFS_BLOCK_COMPRESSED_LZ4 = 1,
    INCFS_BLOCK_COMPRESSED_ZSTD = 2,

    /* Reserve 3 bits for compression alg */
    INCFS_BLOCK_COMPRESSED_MASK = 7,
};

/* Block map entry pointing to an actual location of the data block. */
struct incfs_blockmap_entry {
    /* Offset of the actual data block. Lower 32 bits */
    int32_t me_data_offset_lo;

    /* Offset of the actual data block. Higher 16 bits */
    int16_t me_data_offset_hi;

    /* How many bytes the data actually occupies in the backing file */
    int16_t me_data_size;

    /* Block flags from incfs_block_map_entry_flags */
    int16_t me_flags;
} __packed;

/* Metadata record for locations of file blocks. Type = INCFS_MD_BLOCK_MAP */
struct incfs_blockmap {
    struct incfs_md_header m_header;

    /* Base offset of the array of incfs_blockmap_entry */
    int64_t m_base_offset;

    /* Size of the map entry array in blocks */
    int32_t m_block_count;
} __packed;

/* Metadata record for file signature. Type = INCFS_MD_SIGNATURE */
struct incfs_file_signature {
    struct incfs_md_header sg_header;

    int32_t sg_sig_size; /* The size of the signature. */

    int64_t sg_sig_offset; /* Signature's offset in the backing file */

    int32_t sg_hash_tree_size; /* The size of the hash tree. */

    int64_t sg_hash_tree_offset; /* Hash tree offset in the backing file */
} __packed;

struct incfs_status {
    struct incfs_md_header is_header;

    __le32 is_data_blocks_written; /* Number of data blocks written */

    __le32 is_hash_blocks_written; /* Number of hash blocks written */

    __le32 is_dummy[6]; /* Spare fields */
} __packed;

/*
 * Metadata record for verity signature. Type = INCFS_MD_VERITY_SIGNATURE
 *
 * This record will only exist for verity-enabled files with signatures. Verity
 * enabled files without signatures do not have this record. This signature is
 * checked by fs-verity identically to any other fs-verity signature.
 */
struct incfs_file_verity_signature {
    struct incfs_md_header vs_header;

    /* The size of the signature */
    __le32 vs_size;

    /* Signature's offset in the backing file */
    __le64 vs_offset;
} __packed;

typedef union {
    struct incfs_md_header md_header;
    struct incfs_blockmap blockmap;
    struct incfs_file_signature signature;
    struct incfs_status status;
    struct incfs_file_verity_signature verity_signature;
} md_buffer;

#define INCFS_MAX_METADATA_RECORD_SIZE sizeof(md_buffer)

class Dump {
public:
    Dump(std::string_view backingFile)
          : mBackingFile(android::base::Basename(std::string(backingFile))), mIn(backingFile) {}

    void run() {
        if (!mIn) {
            err() << "bad input file name " << mBackingFile;
            return;
        }

        auto header = read<incfs_file_header>();
        out() << "header: " << hex(header.fh_magic) << ", " << header.fh_version << ", "
              << hex(header.fh_data_block_size) << ", " << header.fh_header_size << ", "
              << header.fh_file_size;
        if (header.fh_magic != INCFS_MAGIC_NUMBER) {
            err() << "bad magic, expected: " << hex(INCFS_MAGIC_NUMBER);
        }
        if (header.fh_version != INCFS_FORMAT_CURRENT_VER) {
            err() << "bad version, expected: " << INCFS_FORMAT_CURRENT_VER;
        }
        if (header.fh_data_block_size != INCFS_DATA_FILE_BLOCK_SIZE) {
            err() << "bad data block size, expected: " << hex(INCFS_DATA_FILE_BLOCK_SIZE);
        }
        if (header.fh_header_size != sizeof(header)) {
            err() << "bad header size, expected: " << sizeof(header);
        }
        {
            auto ostream = out() << "flags: " << hex(header.fh_flags);
            if (header.fh_flags & INCFS_FILE_MAPPED) {
                ostream << " (mapped file)";
            }
        }

        if (header.fh_flags & INCFS_FILE_MAPPED) {
            out() << "source " << toString(header.fh_original_uuid);
            out() << "size " << header.fh_mapped_file_size << " @ "
                  << hex(header.fh_original_offset);
        } else {
            out() << "uuid " << toString(header.fh_uuid);
            out() << "size " << header.fh_file_size;
            out() << "first md offset " << hex(header.fh_first_md_offset);

            int64_t metadataOffset = header.fh_first_md_offset;
            if (metadataOffset >= mIn.tellg()) {
                if (metadataOffset > mIn.tellg()) {
                    out() << "gap of " << metadataOffset - mIn.tellg()
                          << " bytes to the first metadata record";
                }
                incfs_md_header prevMd = {};
                do {
                    dumpMd(metadataOffset, prevMd);
                } while (metadataOffset != 0);
            }
        }
        out() << "finished" << (mIn ? "" : " with read errors");
    }

private:
    auto scopedNesting() {
        ++mNesting;
        auto undoNesting = [this](auto) { --mNesting; };
        return std::unique_ptr<Dump, decltype(undoNesting)>(this, std::move(undoNesting));
    }

    const char* mdType(int type) {
        switch (type) {
            case INCFS_MD_NONE:
                return "none";
            case INCFS_MD_BLOCK_MAP:
                return "block map";
            case INCFS_MD_STATUS:
                return "status";
            case INCFS_MD_SIGNATURE:
                return "signature";
            case INCFS_MD_VERITY_SIGNATURE:
                return "verity signature";
            default:
                return "unknown";
        }
    }

    std::string blockFlags(int flags) {
        if (!flags) {
            return {};
        }
        std::string res = "(";
        auto compression = flags & INCFS_BLOCK_COMPRESSED_MASK;
        if (compression == INCFS_BLOCK_COMPRESSED_LZ4) {
            res += "|lz4-compressed|";
        } else if (flags == INCFS_BLOCK_COMPRESSED_ZSTD) {
            res += "|zstd-compressed|";
        }
        res += ")";
        return res;
    }

    void dumpBlockmap(int64_t offset, int64_t count) {
        auto nesting = scopedNesting();
        mIn.seekg(offset);
        for (int64_t i = 0; i != count; ++i) {
            auto ostream = out() << i << " @ " << hex(mIn.tellg()) << ": [ ";

            auto block = read<incfs_blockmap_entry>();
            auto blockOffset =
                    uint64_t(block.me_data_offset_lo) | (uint64_t(block.me_data_offset_hi) << 32);
            if (blockOffset) {
                ostream << block.me_data_size << " @ " << hex(blockOffset);
            } else {
                ostream << "missing";
            }
            ostream << " ], flags = " << block.me_flags << blockFlags(block.me_flags);
        }
    }

    void dumpTree(int64_t offset, int64_t size) {
        auto nesting = scopedNesting();
        out() << "tree " << offset << " " << size;
    }

    void dumpMd(int64_t& offset, incfs_md_header& prevMd) {
        md_buffer mdBuf = {};
        auto& md = mdBuf.md_header;
        md = readAt<incfs_md_header>(offset);
        out() << "metadata: " << mdType(md.h_md_entry_type) << "(" << int(md.h_md_entry_type)
              << ")";

        auto nesting = scopedNesting();
        out() << "record size: " << md.h_record_size;
        out() << "next md offset: " << hex(md.h_next_md_offset);

        {
            switch (md.h_md_entry_type) {
                case INCFS_MD_NONE:
                    out() << "nothing here";
                    break;
                case INCFS_MD_BLOCK_MAP: {
                    auto& bm = mdBuf.blockmap;
                    bm = readAt<decltype(bm)>(offset);
                    out() << "offset:      " << hex(bm.m_base_offset);
                    out() << "block count: " << bm.m_block_count;
                    dumpBlockmap(bm.m_base_offset, bm.m_block_count);
                    break;
                }
                case INCFS_MD_SIGNATURE: {
                    auto& sig = mdBuf.signature;
                    sig = readAt<decltype(sig)>(offset);
                    out() << "signature size:   " << sig.sg_sig_size;
                    out() << "signature offset: " << hex(sig.sg_sig_offset);
                    out() << "hash tree size:   " << sig.sg_hash_tree_size;
                    out() << "hash tree offset: " << hex(sig.sg_hash_tree_offset);
                    dumpTree(sig.sg_hash_tree_offset, sig.sg_hash_tree_size);
                    break;
                }
                case INCFS_MD_STATUS: {
                    auto& st = mdBuf.status;
                    st = readAt<decltype(st)>(offset);
                    out() << "data blocks written: " << st.is_data_blocks_written;
                    out() << "hash blocks written: " << st.is_hash_blocks_written;
                    break;
                }
                case INCFS_MD_VERITY_SIGNATURE: {
                    auto& vs = mdBuf.verity_signature;
                    vs = readAt<decltype(vs)>(offset);
                    out() << "verity signature size:   " << vs.vs_size;
                    out() << "verity signature offset: " << hex(vs.vs_offset);
                    break;
                }
                default:
                    out() << "don't know how to handle it";
                    break;
            }
        }

        updateMaxPos();
        prevMd = md;
        offset = md.h_next_md_offset;
    }

    struct OstreamWrapper {
        explicit OstreamWrapper(std::ostream& wrapped) : mWrapped(&wrapped) {}
        OstreamWrapper(OstreamWrapper&& other) noexcept
              : mWrapped(std::exchange(other.mWrapped, nullptr)) {}

        ~OstreamWrapper() {
            if (mWrapped) {
                *mWrapped << '\n';
            }
        }

        template <class T>
        OstreamWrapper& operator<<(const T& t) & {
            *mWrapped << t;
            return *this;
        }
        template <class T>
        OstreamWrapper&& operator<<(const T& t) && {
            *this << t;
            return std::move(*this);
        }

    private:
        std::ostream* mWrapped;
    };

    static std::string hex(uint64_t t) {
        char buf[32] = {};
        snprintf(buf, std::size(buf) - 1, "0x%llx", (unsigned long long)t);
        return buf;
    }

    static std::string toString(incfs_uuid_t uuid) {
        std::string res;
        for (unsigned char b : uuid.bytes) {
            char buf[3] = {};
            snprintf(buf, std::size(buf) - 1, "%02x", (unsigned int)b);
            res += buf;
        }
        return res;
    }

    OstreamWrapper out() const {
        nesting(std::cout);
        std::cout << "[" << mBackingFile << "] ";
        return OstreamWrapper(std::cout);
    }

    OstreamWrapper err() const {
        nesting(std::cerr);
        std::cerr << "[" << mBackingFile << "] ";
        return OstreamWrapper(std::cerr);
    }

    void nesting(std::ostream& out) const {
        for (int i = 0; i < mNesting; ++i) {
            out << "   ";
        }
    }

    template <class T>
    std::remove_reference_t<T> read() {
        std::remove_reference_t<T> res;
        mIn.read((char*)&res, sizeof(res));
        return res;
    }

    template <class T>
    std::remove_reference_t<T> readAt(int64_t pos) {
        mIn.seekg(pos);
        return read<T>();
    }

    void skip(int64_t count) { mIn.seekg(count, std::ios_base::cur); }

    void updateMaxPos() { mMaxDumpedPos = std::max<int64_t>(mMaxDumpedPos, mIn.tellg()); }

    std::string mBackingFile;
    std::ifstream mIn;
    int mNesting = 0;
    int64_t mMaxDumpedPos = 0;
};

} // namespace

namespace android::incfs {

void dump(std::string_view backingFile) {
    Dump(backingFile).run();
}

} // namespace android::incfs
