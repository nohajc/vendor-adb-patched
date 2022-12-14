/*
 ** Copyright 2011, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include "BlobCache.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdio.h>

#include <memory>

namespace android {

template <typename T>
using sp = std::shared_ptr<T>;

class BlobCacheTest : public ::testing::Test {
protected:
    enum {
        OK = 0,
        BAD_VALUE = -EINVAL,
    };

    enum {
        MAX_KEY_SIZE = 6,
        MAX_VALUE_SIZE = 8,
        MAX_TOTAL_SIZE = 13,
    };

    virtual void SetUp() { mBC.reset(new BlobCache(MAX_KEY_SIZE, MAX_VALUE_SIZE, MAX_TOTAL_SIZE)); }

    virtual void TearDown() { mBC.reset(); }

    std::unique_ptr<BlobCache> mBC;
};

TEST_F(BlobCacheTest, CacheSingleValueSucceeds) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_F(BlobCacheTest, CacheTwoValuesSucceeds) {
    unsigned char buf[2] = {0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("ab", 2, "cd", 2));
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("ef", 2, "gh", 2));
    ASSERT_EQ(size_t(2), mBC->get("ab", 2, buf, 2));
    ASSERT_EQ('c', buf[0]);
    ASSERT_EQ('d', buf[1]);
    ASSERT_EQ(size_t(2), mBC->get("ef", 2, buf, 2));
    ASSERT_EQ('g', buf[0]);
    ASSERT_EQ('h', buf[1]);
}

TEST_F(BlobCacheTest, GetOnlyWritesInsideBounds) {
    unsigned char buf[6] = {0xee, 0xee, 0xee, 0xee, 0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, buf + 1, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ('e', buf[1]);
    ASSERT_EQ('f', buf[2]);
    ASSERT_EQ('g', buf[3]);
    ASSERT_EQ('h', buf[4]);
    ASSERT_EQ(0xee, buf[5]);
}

TEST_F(BlobCacheTest, GetOnlyWritesIfBufferIsLargeEnough) {
    unsigned char buf[3] = {0xee, 0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, buf, 3));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
}

TEST_F(BlobCacheTest, GetDoesntAccessNullBuffer) {
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, nullptr, 0));
}

TEST_F(BlobCacheTest, MultipleSetsCacheLatestValue) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "ijkl", 4));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('i', buf[0]);
    ASSERT_EQ('j', buf[1]);
    ASSERT_EQ('k', buf[2]);
    ASSERT_EQ('l', buf[3]);
}

TEST_F(BlobCacheTest, SecondSetKeepsFirstValueIfTooLarge) {
    unsigned char buf[MAX_VALUE_SIZE + 1] = {0xee, 0xee, 0xee, 0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, "efgh", 4));
    ASSERT_EQ(BlobCache::InsertResult::kValueTooBig, mBC->set("abcd", 4, buf, MAX_VALUE_SIZE + 1));
    ASSERT_EQ(size_t(4), mBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_F(BlobCacheTest, DoesntCacheIfKeyIsTooBig) {
    char key[MAX_KEY_SIZE + 1];
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    for (int i = 0; i < MAX_KEY_SIZE + 1; i++) {
        key[i] = 'a';
    }
    ASSERT_EQ(BlobCache::InsertResult::kKeyTooBig, mBC->set(key, MAX_KEY_SIZE + 1, "bbbb", 4));
    ASSERT_EQ(size_t(0), mBC->get(key, MAX_KEY_SIZE + 1, buf, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
    ASSERT_EQ(0xee, buf[3]);
}

TEST_F(BlobCacheTest, DoesntCacheIfValueIsTooBig) {
    char buf[MAX_VALUE_SIZE + 1];
    for (int i = 0; i < MAX_VALUE_SIZE + 1; i++) {
        buf[i] = 'b';
    }
    ASSERT_EQ(BlobCache::InsertResult::kValueTooBig, mBC->set("abcd", 4, buf, MAX_VALUE_SIZE + 1));
    for (int i = 0; i < MAX_VALUE_SIZE + 1; i++) {
        buf[i] = 0xee;
    }
    ASSERT_EQ(size_t(0), mBC->get("abcd", 4, buf, MAX_VALUE_SIZE + 1));
    for (int i = 0; i < MAX_VALUE_SIZE + 1; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ(0xee, buf[i]);
    }
}

TEST_F(BlobCacheTest, DoesntCacheIfKeyValuePairIsTooBig) {
    // Check a testing assumptions
    ASSERT_TRUE(MAX_TOTAL_SIZE < MAX_KEY_SIZE + MAX_VALUE_SIZE);
    ASSERT_TRUE(MAX_KEY_SIZE < MAX_TOTAL_SIZE);

    enum { bufSize = MAX_TOTAL_SIZE - MAX_KEY_SIZE + 1 };

    char key[MAX_KEY_SIZE];
    char buf[bufSize];
    for (int i = 0; i < MAX_KEY_SIZE; i++) {
        key[i] = 'a';
    }
    for (int i = 0; i < bufSize; i++) {
        buf[i] = 'b';
    }

    ASSERT_EQ(BlobCache::InsertResult::kCombinedTooBig,
              mBC->set(key, MAX_KEY_SIZE, buf, MAX_VALUE_SIZE));
    ASSERT_EQ(size_t(0), mBC->get(key, MAX_KEY_SIZE, nullptr, 0));
}

TEST_F(BlobCacheTest, CacheMaxKeySizeSucceeds) {
    char key[MAX_KEY_SIZE];
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    for (int i = 0; i < MAX_KEY_SIZE; i++) {
        key[i] = 'a';
    }
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set(key, MAX_KEY_SIZE, "wxyz", 4));
    ASSERT_EQ(size_t(4), mBC->get(key, MAX_KEY_SIZE, buf, 4));
    ASSERT_EQ('w', buf[0]);
    ASSERT_EQ('x', buf[1]);
    ASSERT_EQ('y', buf[2]);
    ASSERT_EQ('z', buf[3]);
}

TEST_F(BlobCacheTest, CacheMaxValueSizeSucceeds) {
    char buf[MAX_VALUE_SIZE];
    for (int i = 0; i < MAX_VALUE_SIZE; i++) {
        buf[i] = 'b';
    }
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("abcd", 4, buf, MAX_VALUE_SIZE));
    for (int i = 0; i < MAX_VALUE_SIZE; i++) {
        buf[i] = 0xee;
    }
    ASSERT_EQ(size_t(MAX_VALUE_SIZE), mBC->get("abcd", 4, buf, MAX_VALUE_SIZE));
    for (int i = 0; i < MAX_VALUE_SIZE; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ('b', buf[i]);
    }
}

TEST_F(BlobCacheTest, CacheMaxKeyValuePairSizeSucceeds) {
    // Check a testing assumption
    ASSERT_TRUE(MAX_KEY_SIZE < MAX_TOTAL_SIZE);

    enum { bufSize = MAX_TOTAL_SIZE - MAX_KEY_SIZE };

    char key[MAX_KEY_SIZE];
    char buf[bufSize];
    for (int i = 0; i < MAX_KEY_SIZE; i++) {
        key[i] = 'a';
    }
    for (int i = 0; i < bufSize; i++) {
        buf[i] = 'b';
    }

    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set(key, MAX_KEY_SIZE, buf, bufSize));
    ASSERT_EQ(size_t(bufSize), mBC->get(key, MAX_KEY_SIZE, nullptr, 0));
}

// Verify that kNotEnoughSpace is returned from BlobCache::set when expected.
// Note: This relies on internal knowledge of how BlobCache works.
TEST_F(BlobCacheTest, NotEnoughSpace) {
    // Insert a small entry into the cache.
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("x", 1, "y", 1));

    // Attempt to put a max size entry into the cache. If the cache were empty,
    // as in CacheMaxKeyValuePairSizeSucceeds, this would succeed. Based on the
    // current logic of BlobCache, the small entry is not big enough to allow it
    // to be cleaned to insert the new entry.
    ASSERT_TRUE(MAX_KEY_SIZE < MAX_TOTAL_SIZE);

    enum { bufSize = MAX_TOTAL_SIZE - MAX_KEY_SIZE };

    char key[MAX_KEY_SIZE];
    char buf[bufSize];
    for (int i = 0; i < MAX_KEY_SIZE; i++) {
        key[i] = 'a';
    }
    for (int i = 0; i < bufSize; i++) {
        buf[i] = 'b';
    }

    ASSERT_EQ(BlobCache::InsertResult::kNotEnoughSpace, mBC->set(key, MAX_KEY_SIZE, buf, bufSize));
    ASSERT_EQ(0, mBC->get(key, MAX_KEY_SIZE, nullptr, 0));

    // The original entry remains in the cache.
    unsigned char buf2[1] = {0xee};
    ASSERT_EQ(size_t(1), mBC->get("x", 1, buf2, 1));
    ASSERT_EQ('y', buf2[0]);
}

TEST_F(BlobCacheTest, CacheMinKeyAndValueSizeSucceeds) {
    unsigned char buf[1] = {0xee};
    ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set("x", 1, "y", 1));
    ASSERT_EQ(size_t(1), mBC->get("x", 1, buf, 1));
    ASSERT_EQ('y', buf[0]);
}

TEST_F(BlobCacheTest, CacheSizeDoesntExceedTotalLimit) {
    for (int i = 0; i < 256; i++) {
        uint8_t k = i;
        mBC->set(&k, 1, "x", 1);
    }
    int numCached = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t k = i;
        if (mBC->get(&k, 1, nullptr, 0) == 1) {
            numCached++;
        }
    }
    ASSERT_GE(MAX_TOTAL_SIZE / 2, numCached);
}

TEST_F(BlobCacheTest, ExceedingTotalLimitHalvesCacheSize) {
    // Fill up the entire cache with 1 char key/value pairs.
    const int maxEntries = MAX_TOTAL_SIZE / 2;
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        ASSERT_EQ(BlobCache::InsertResult::kInserted, mBC->set(&k, 1, "x", 1));
    }
    // Insert one more entry, causing a cache overflow.
    {
        uint8_t k = maxEntries;
        ASSERT_EQ(BlobCache::InsertResult::kDidClean, mBC->set(&k, 1, "x", 1));
    }
    // Count the number of entries in the cache.
    int numCached = 0;
    for (int i = 0; i < maxEntries + 1; i++) {
        uint8_t k = i;
        if (mBC->get(&k, 1, nullptr, 0) == 1) {
            numCached++;
        }
    }
    ASSERT_EQ(maxEntries / 2 + 1, numCached);
}

TEST_F(BlobCacheTest, InvalidKeySize) {
    ASSERT_EQ(BlobCache::InsertResult::kInvalidKeySize, mBC->set("", 0, "efgh", 4));
}

TEST_F(BlobCacheTest, InvalidValueSize) {
    ASSERT_EQ(BlobCache::InsertResult::kInvalidValueSize, mBC->set("abcd", 4, "", 0));
}

class BlobCacheFlattenTest : public BlobCacheTest {
protected:
    virtual void SetUp() {
        BlobCacheTest::SetUp();
        mBC2.reset(new BlobCache(MAX_KEY_SIZE, MAX_VALUE_SIZE, MAX_TOTAL_SIZE));
    }

    virtual void TearDown() {
        mBC2.reset();
        BlobCacheTest::TearDown();
    }

    void roundTrip() {
        size_t size = mBC->getFlattenedSize();
        uint8_t* flat = new uint8_t[size];
        ASSERT_EQ(OK, mBC->flatten(flat, size));
        ASSERT_EQ(OK, mBC2->unflatten(flat, size));
        delete[] flat;
    }

    sp<BlobCache> mBC2;
};

TEST_F(BlobCacheFlattenTest, FlattenOneValue) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mBC->set("abcd", 4, "efgh", 4);
    roundTrip();
    ASSERT_EQ(size_t(4), mBC2->get("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_F(BlobCacheFlattenTest, FlattenFullCache) {
    // Fill up the entire cache with 1 char key/value pairs.
    const int maxEntries = MAX_TOTAL_SIZE / 2;
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        mBC->set(&k, 1, &k, 1);
    }

    roundTrip();

    // Verify the deserialized cache
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        uint8_t v = 0xee;
        ASSERT_EQ(size_t(1), mBC2->get(&k, 1, &v, 1));
        ASSERT_EQ(k, v);
    }
}

TEST_F(BlobCacheFlattenTest, FlattenDoesntChangeCache) {
    // Fill up the entire cache with 1 char key/value pairs.
    const int maxEntries = MAX_TOTAL_SIZE / 2;
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        mBC->set(&k, 1, &k, 1);
    }

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));
    delete[] flat;

    // Verify the cache that we just serialized
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        uint8_t v = 0xee;
        ASSERT_EQ(size_t(1), mBC->get(&k, 1, &v, 1));
        ASSERT_EQ(k, v);
    }
}

TEST_F(BlobCacheFlattenTest, FlattenCatchesBufferTooSmall) {
    // Fill up the entire cache with 1 char key/value pairs.
    const int maxEntries = MAX_TOTAL_SIZE / 2;
    for (int i = 0; i < maxEntries; i++) {
        uint8_t k = i;
        mBC->set(&k, 1, &k, 1);
    }

    size_t size = mBC->getFlattenedSize() - 1;
    uint8_t* flat = new uint8_t[size];
    // ASSERT_EQ(BAD_VALUE, mBC->flatten(flat, size));
    // TODO: The above fails. I expect this is so because getFlattenedSize()
    // overstimates the size by using PROPERTY_VALUE_MAX.
    delete[] flat;
}

TEST_F(BlobCacheFlattenTest, UnflattenCatchesBadMagic) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mBC->set("abcd", 4, "efgh", 4);

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));
    flat[1] = ~flat[1];

    // Bad magic should cause an error.
    ASSERT_EQ(BAD_VALUE, mBC2->unflatten(flat, size));
    delete[] flat;

    // The error should cause the unflatten to result in an empty cache
    ASSERT_EQ(size_t(0), mBC2->get("abcd", 4, buf, 4));
}

TEST_F(BlobCacheFlattenTest, UnflattenCatchesBadBlobCacheVersion) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mBC->set("abcd", 4, "efgh", 4);

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));
    flat[5] = ~flat[5];

    // Version mismatches shouldn't cause errors, but should not use the
    // serialized entries
    ASSERT_EQ(OK, mBC2->unflatten(flat, size));
    delete[] flat;

    // The version mismatch should cause the unflatten to result in an empty
    // cache
    ASSERT_EQ(size_t(0), mBC2->get("abcd", 4, buf, 4));
}

TEST_F(BlobCacheFlattenTest, UnflattenCatchesBadBlobCacheDeviceVersion) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mBC->set("abcd", 4, "efgh", 4);

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));
    flat[10] = ~flat[10];

    // Version mismatches shouldn't cause errors, but should not use the
    // serialized entries
    ASSERT_EQ(OK, mBC2->unflatten(flat, size));
    delete[] flat;

    // The version mismatch should cause the unflatten to result in an empty
    // cache
    ASSERT_EQ(size_t(0), mBC2->get("abcd", 4, buf, 4));
}

TEST_F(BlobCacheFlattenTest, UnflattenCatchesBufferTooSmall) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mBC->set("abcd", 4, "efgh", 4);

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));

    // A buffer truncation shouldt cause an error
    // ASSERT_EQ(BAD_VALUE, mBC2->unflatten(flat, size-1));
    // TODO: The above appears to fail because getFlattenedSize() is
    // conservative.
    delete[] flat;

    // The error should cause the unflatten to result in an empty cache
    ASSERT_EQ(size_t(0), mBC2->get("abcd", 4, buf, 4));
}

// Test for a divide by zero bug (b/239862516). Before the fix, unflatten() would not reset
// mTotalSize when it encountered an error, which would trigger division by 0 in clean() in the
// right conditions.
TEST_F(BlobCacheFlattenTest, SetAfterFailedUnflatten) {
    // isCleanable() must be true, so mTotalSize must be > mMaxTotalSize / 2 after unflattening
    // after one entry is lost. To make this the case, MaxTotalSize is 30 and three 10 sized
    // entries are used. One of those entries is lost, resulting in mTotalSize=20
    const size_t kMaxKeySize = 10;
    const size_t kMaxValueSize = 10;
    const size_t kMaxTotalSize = 30;
    mBC.reset(new BlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize));
    mBC2.reset(new BlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize));
    mBC->set("aaaaa", 5, "aaaaa", 5);
    mBC->set("bbbbb", 5, "bbbbb", 5);
    mBC->set("ccccc", 5, "ccccc", 5);

    size_t size = mBC->getFlattenedSize();
    uint8_t* flat = new uint8_t[size];
    ASSERT_EQ(OK, mBC->flatten(flat, size));

    ASSERT_EQ(BAD_VALUE, mBC2->unflatten(flat, size - 10));
    delete[] flat;

    // This line will trigger clean() which caused a crash.
    mBC2->set("dddddddddd", 10, "dddddddddd", 10);
}

} // namespace android
