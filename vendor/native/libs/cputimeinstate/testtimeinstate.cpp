/*
 * Copyright (C) 2018 The Android Open Source Project
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


#include <bpf_timeinstate.h>

#include <sys/sysinfo.h>

#include <pthread.h>
#include <semaphore.h>
#include <numeric>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <cputimeinstate.h>
#include <libbpf.h>

namespace android {
namespace bpf {

static constexpr uint64_t NSEC_PER_SEC = 1000000000;
static constexpr uint64_t NSEC_PER_YEAR = NSEC_PER_SEC * 60 * 60 * 24 * 365;

using std::vector;

TEST(TimeInStateTest, IsTrackingSupported) {
    isTrackingUidTimesSupported();
    SUCCEED();
}

TEST(TimeInStateTest, TotalTimeInState) {
    auto times = getTotalCpuFreqTimes();
    ASSERT_TRUE(times.has_value());
    EXPECT_FALSE(times->empty());
}

TEST(TimeInStateTest, SingleUidTimeInState) {
    auto times = getUidCpuFreqTimes(0);
    ASSERT_TRUE(times.has_value());
    EXPECT_FALSE(times->empty());
}

TEST(TimeInStateTest, SingleUidConcurrentTimes) {
    auto concurrentTimes = getUidConcurrentTimes(0);
    ASSERT_TRUE(concurrentTimes.has_value());
    ASSERT_FALSE(concurrentTimes->active.empty());
    ASSERT_FALSE(concurrentTimes->policy.empty());

    uint64_t policyEntries = 0;
    for (const auto &policyTimeVec : concurrentTimes->policy) policyEntries += policyTimeVec.size();
    ASSERT_EQ(concurrentTimes->active.size(), policyEntries);
}

static void TestConcurrentTimesConsistent(const struct concurrent_time_t &concurrentTime) {
    size_t maxPolicyCpus = 0;
    for (const auto &vec : concurrentTime.policy) {
        maxPolicyCpus = std::max(maxPolicyCpus, vec.size());
    }
    uint64_t policySum = 0;
    for (size_t i = 0; i < maxPolicyCpus; ++i) {
        for (const auto &vec : concurrentTime.policy) {
            if (i < vec.size()) policySum += vec[i];
        }
        ASSERT_LE(concurrentTime.active[i], policySum);
        policySum -= concurrentTime.active[i];
    }
    policySum = 0;
    for (size_t i = 0; i < concurrentTime.active.size(); ++i) {
        for (const auto &vec : concurrentTime.policy) {
            if (i < vec.size()) policySum += vec[vec.size() - 1 - i];
        }
        auto activeSum = concurrentTime.active[concurrentTime.active.size() - 1 - i];
        // This check is slightly flaky because we may read a map entry in the middle of an update
        // when active times have been updated but policy times have not. This happens infrequently
        // and can be distinguished from more serious bugs by re-running the test: if the underlying
        // data itself is inconsistent, the test will fail every time.
        ASSERT_LE(activeSum, policySum);
        policySum -= activeSum;
    }
}

static void TestUidTimesConsistent(const std::vector<std::vector<uint64_t>> &timeInState,
                                   const struct concurrent_time_t &concurrentTime) {
    ASSERT_NO_FATAL_FAILURE(TestConcurrentTimesConsistent(concurrentTime));
    ASSERT_EQ(timeInState.size(), concurrentTime.policy.size());
    uint64_t policySum = 0;
    for (uint32_t i = 0; i < timeInState.size(); ++i) {
        uint64_t tisSum =
                std::accumulate(timeInState[i].begin(), timeInState[i].end(), (uint64_t)0);
        uint64_t concurrentSum = std::accumulate(concurrentTime.policy[i].begin(),
                                                 concurrentTime.policy[i].end(), (uint64_t)0);
        if (tisSum < concurrentSum)
            ASSERT_LE(concurrentSum - tisSum, NSEC_PER_SEC);
        else
            ASSERT_LE(tisSum - concurrentSum, NSEC_PER_SEC);
        policySum += concurrentSum;
    }
    uint64_t activeSum = std::accumulate(concurrentTime.active.begin(), concurrentTime.active.end(),
                                         (uint64_t)0);
    EXPECT_EQ(activeSum, policySum);
}

TEST(TimeInStateTest, SingleUidTimesConsistent) {
    auto times = getUidCpuFreqTimes(0);
    ASSERT_TRUE(times.has_value());

    auto concurrentTimes = getUidConcurrentTimes(0);
    ASSERT_TRUE(concurrentTimes.has_value());

    ASSERT_NO_FATAL_FAILURE(TestUidTimesConsistent(*times, *concurrentTimes));
}

TEST(TimeInStateTest, AllUidTimeInState) {
    uint64_t zero = 0;
    auto maps = {getUidsCpuFreqTimes(), getUidsUpdatedCpuFreqTimes(&zero)};
    for (const auto &map : maps) {
        ASSERT_TRUE(map.has_value());

        ASSERT_FALSE(map->empty());

        vector<size_t> sizes;
        auto firstEntry = map->begin()->second;
        for (const auto &subEntry : firstEntry) sizes.emplace_back(subEntry.size());

        for (const auto &vec : *map) {
            ASSERT_EQ(vec.second.size(), sizes.size());
            for (size_t i = 0; i < vec.second.size(); ++i) ASSERT_EQ(vec.second[i].size(), sizes[i]);
        }
    }
}

void TestCheckUpdate(const std::vector<std::vector<uint64_t>> &before,
                     const std::vector<std::vector<uint64_t>> &after) {
    ASSERT_EQ(before.size(), after.size());
    uint64_t sumBefore = 0, sumAfter = 0;
    for (size_t i = 0; i < before.size(); ++i) {
        ASSERT_EQ(before[i].size(), after[i].size());
        for (size_t j = 0; j < before[i].size(); ++j) {
            // Times should never decrease
            ASSERT_LE(before[i][j], after[i][j]);
        }
        sumBefore += std::accumulate(before[i].begin(), before[i].end(), (uint64_t)0);
        sumAfter += std::accumulate(after[i].begin(), after[i].end(), (uint64_t)0);
    }
    ASSERT_LE(sumBefore, sumAfter);
    ASSERT_LE(sumAfter - sumBefore, NSEC_PER_SEC);
}

TEST(TimeInStateTest, AllUidUpdatedTimeInState) {
    uint64_t lastUpdate = 0;
    auto map1 = getUidsUpdatedCpuFreqTimes(&lastUpdate);
    ASSERT_TRUE(map1.has_value());
    ASSERT_FALSE(map1->empty());
    ASSERT_NE(lastUpdate, (uint64_t)0);
    uint64_t oldLastUpdate = lastUpdate;

    // Sleep briefly to trigger a context switch, ensuring we see at least one update.
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;
    nanosleep (&ts, NULL);

    auto map2 = getUidsUpdatedCpuFreqTimes(&lastUpdate);
    ASSERT_TRUE(map2.has_value());
    ASSERT_FALSE(map2->empty());
    ASSERT_NE(lastUpdate, oldLastUpdate);

    bool someUidsExcluded = false;
    for (const auto &[uid, v] : *map1) {
        if (map2->find(uid) == map2->end()) {
            someUidsExcluded = true;
            break;
        }
    }
    ASSERT_TRUE(someUidsExcluded);

    for (const auto &[uid, newTimes] : *map2) {
        ASSERT_NE(map1->find(uid), map1->end());
        ASSERT_NO_FATAL_FAILURE(TestCheckUpdate((*map1)[uid], newTimes));
    }
}

TEST(TimeInStateTest, TotalAndAllUidTimeInStateConsistent) {
    auto allUid = getUidsCpuFreqTimes();
    auto total = getTotalCpuFreqTimes();

    ASSERT_TRUE(allUid.has_value() && total.has_value());

    // Check the number of policies.
    ASSERT_EQ(allUid->at(0).size(), total->size());

    for (uint32_t policyIdx = 0; policyIdx < total->size(); ++policyIdx) {
        std::vector<uint64_t> totalTimes = total->at(policyIdx);
        uint32_t totalFreqsCount = totalTimes.size();
        std::vector<uint64_t> allUidTimes(totalFreqsCount, 0);
        for (auto const &[uid, uidTimes]: *allUid) {
            for (uint32_t freqIdx = 0; freqIdx < uidTimes[policyIdx].size(); ++freqIdx) {
                allUidTimes[std::min(freqIdx, totalFreqsCount - 1)] += uidTimes[policyIdx][freqIdx];
            }
        }

        for (uint32_t freqIdx = 0; freqIdx < totalFreqsCount; ++freqIdx) {
            ASSERT_LE(allUidTimes[freqIdx], totalTimes[freqIdx]);
        }
    }
}

TEST(TimeInStateTest, SingleAndAllUidTimeInStateConsistent) {
    uint64_t zero = 0;
    auto maps = {getUidsCpuFreqTimes(), getUidsUpdatedCpuFreqTimes(&zero)};
    for (const auto &map : maps) {
        ASSERT_TRUE(map.has_value());
        ASSERT_FALSE(map->empty());

        for (const auto &kv : *map) {
            uint32_t uid = kv.first;
            auto times1 = kv.second;
            auto times2 = getUidCpuFreqTimes(uid);
            ASSERT_TRUE(times2.has_value());

            ASSERT_EQ(times1.size(), times2->size());
            for (uint32_t i = 0; i < times1.size(); ++i) {
                ASSERT_EQ(times1[i].size(), (*times2)[i].size());
                for (uint32_t j = 0; j < times1[i].size(); ++j) {
                    ASSERT_LE((*times2)[i][j] - times1[i][j], NSEC_PER_SEC);
                }
            }
        }
    }
}

TEST(TimeInStateTest, AllUidConcurrentTimes) {
    uint64_t zero = 0;
    auto maps = {getUidsConcurrentTimes(), getUidsUpdatedConcurrentTimes(&zero)};
    for (const auto &map : maps) {
        ASSERT_TRUE(map.has_value());
        ASSERT_FALSE(map->empty());

        auto firstEntry = map->begin()->second;
        for (const auto &kv : *map) {
            ASSERT_EQ(kv.second.active.size(), firstEntry.active.size());
            ASSERT_EQ(kv.second.policy.size(), firstEntry.policy.size());
            for (size_t i = 0; i < kv.second.policy.size(); ++i) {
                ASSERT_EQ(kv.second.policy[i].size(), firstEntry.policy[i].size());
            }
        }
    }
}

TEST(TimeInStateTest, AllUidUpdatedConcurrentTimes) {
    uint64_t lastUpdate = 0;
    auto map1 = getUidsUpdatedConcurrentTimes(&lastUpdate);
    ASSERT_TRUE(map1.has_value());
    ASSERT_FALSE(map1->empty());
    ASSERT_NE(lastUpdate, (uint64_t)0);

    // Sleep briefly to trigger a context switch, ensuring we see at least one update.
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;
    nanosleep (&ts, NULL);

    uint64_t oldLastUpdate = lastUpdate;
    auto map2 = getUidsUpdatedConcurrentTimes(&lastUpdate);
    ASSERT_TRUE(map2.has_value());
    ASSERT_FALSE(map2->empty());
    ASSERT_NE(lastUpdate, oldLastUpdate);

    bool someUidsExcluded = false;
    for (const auto &[uid, v] : *map1) {
        if (map2->find(uid) == map2->end()) {
            someUidsExcluded = true;
            break;
        }
    }
    ASSERT_TRUE(someUidsExcluded);

    for (const auto &[uid, newTimes] : *map2) {
        ASSERT_NE(map1->find(uid), map1->end());
        ASSERT_NO_FATAL_FAILURE(TestCheckUpdate({(*map1)[uid].active},{newTimes.active}));
        ASSERT_NO_FATAL_FAILURE(TestCheckUpdate((*map1)[uid].policy, newTimes.policy));
    }
}

TEST(TimeInStateTest, SingleAndAllUidConcurrentTimesConsistent) {
    uint64_t zero = 0;
    auto maps = {getUidsConcurrentTimes(), getUidsUpdatedConcurrentTimes(&zero)};
    for (const auto &map : maps) {
        ASSERT_TRUE(map.has_value());
        for (const auto &kv : *map) {
            uint32_t uid = kv.first;
            auto times1 = kv.second;
            auto times2 = getUidConcurrentTimes(uid);
            ASSERT_TRUE(times2.has_value());
            for (uint32_t i = 0; i < times1.active.size(); ++i) {
                ASSERT_LE(times2->active[i] - times1.active[i], NSEC_PER_SEC);
            }
            for (uint32_t i = 0; i < times1.policy.size(); ++i) {
                for (uint32_t j = 0; j < times1.policy[i].size(); ++j) {
                    ASSERT_LE(times2->policy[i][j] - times1.policy[i][j], NSEC_PER_SEC);
                }
            }
        }
    }
}

void TestCheckDelta(uint64_t before, uint64_t after) {
    // Times should never decrease
    ASSERT_LE(before, after);
    // UID can't have run for more than ~1s on each CPU
    ASSERT_LE(after - before, NSEC_PER_SEC * 2 * get_nprocs_conf());
}

TEST(TimeInStateTest, TotalTimeInStateMonotonic) {
    auto before = getTotalCpuFreqTimes();
    ASSERT_TRUE(before.has_value());
    sleep(1);
    auto after = getTotalCpuFreqTimes();
    ASSERT_TRUE(after.has_value());

    for (uint32_t policyIdx = 0; policyIdx < after->size(); ++policyIdx) {
        auto timesBefore = before->at(policyIdx);
        auto timesAfter = after->at(policyIdx);
        for (uint32_t freqIdx = 0; freqIdx < timesAfter.size(); ++freqIdx) {
            ASSERT_NO_FATAL_FAILURE(TestCheckDelta(timesBefore[freqIdx], timesAfter[freqIdx]));
        }
    }
}

TEST(TimeInStateTest, AllUidTimeInStateMonotonic) {
    auto map1 = getUidsCpuFreqTimes();
    ASSERT_TRUE(map1.has_value());
    sleep(1);
    auto map2 = getUidsCpuFreqTimes();
    ASSERT_TRUE(map2.has_value());

    for (const auto &kv : *map1) {
        uint32_t uid = kv.first;
        auto times = kv.second;
        ASSERT_NE(map2->find(uid), map2->end());
        for (uint32_t policy = 0; policy < times.size(); ++policy) {
            for (uint32_t freqIdx = 0; freqIdx < times[policy].size(); ++freqIdx) {
                auto before = times[policy][freqIdx];
                auto after = (*map2)[uid][policy][freqIdx];
                ASSERT_NO_FATAL_FAILURE(TestCheckDelta(before, after));
            }
        }
    }
}

TEST(TimeInStateTest, AllUidConcurrentTimesMonotonic) {
    auto map1 = getUidsConcurrentTimes();
    ASSERT_TRUE(map1.has_value());
    ASSERT_FALSE(map1->empty());
    sleep(1);
    auto map2 = getUidsConcurrentTimes();
    ASSERT_TRUE(map2.has_value());
    ASSERT_FALSE(map2->empty());

    for (const auto &kv : *map1) {
        uint32_t uid = kv.first;
        auto times = kv.second;
        ASSERT_NE(map2->find(uid), map2->end());
        for (uint32_t i = 0; i < times.active.size(); ++i) {
            auto before = times.active[i];
            auto after = (*map2)[uid].active[i];
            ASSERT_NO_FATAL_FAILURE(TestCheckDelta(before, after));
        }
        for (uint32_t policy = 0; policy < times.policy.size(); ++policy) {
            for (uint32_t idx = 0; idx < times.policy[policy].size(); ++idx) {
                auto before = times.policy[policy][idx];
                auto after = (*map2)[uid].policy[policy][idx];
                ASSERT_NO_FATAL_FAILURE(TestCheckDelta(before, after));
            }
        }
    }
}

TEST(TimeInStateTest, AllUidTimeInStateSanityCheck) {
    uint64_t zero = 0;
    auto maps = {getUidsCpuFreqTimes(), getUidsUpdatedCpuFreqTimes(&zero)};
    for (const auto &map : maps) {
        ASSERT_TRUE(map.has_value());

        bool foundLargeValue = false;
        for (const auto &kv : *map) {
            for (const auto &timeVec : kv.second) {
                for (const auto &time : timeVec) {
                    ASSERT_LE(time, NSEC_PER_YEAR);
                    if (time > UINT32_MAX) foundLargeValue = true;
                }
            }
        }
        // UINT32_MAX nanoseconds is less than 5 seconds, so if every part of our pipeline is using
        // uint64_t as expected, we should have some times higher than that.
        ASSERT_TRUE(foundLargeValue);
    }
}

TEST(TimeInStateTest, AllUidConcurrentTimesSanityCheck) {
    uint64_t zero = 0;
    auto maps = {getUidsConcurrentTimes(), getUidsUpdatedConcurrentTimes(&zero)};
    for (const auto &concurrentMap : maps) {
        ASSERT_TRUE(concurrentMap);

        bool activeFoundLargeValue = false;
        bool policyFoundLargeValue = false;
        for (const auto &kv : *concurrentMap) {
            for (const auto &time : kv.second.active) {
                ASSERT_LE(time, NSEC_PER_YEAR);
                if (time > UINT32_MAX) activeFoundLargeValue = true;
            }
            for (const auto &policyTimeVec : kv.second.policy) {
                for (const auto &time : policyTimeVec) {
                    ASSERT_LE(time, NSEC_PER_YEAR);
                    if (time > UINT32_MAX) policyFoundLargeValue = true;
                }
            }
        }
        // UINT32_MAX nanoseconds is less than 5 seconds, so if every part of our pipeline is using
        // uint64_t as expected, we should have some times higher than that.
        ASSERT_TRUE(activeFoundLargeValue);
        ASSERT_TRUE(policyFoundLargeValue);
    }
}

TEST(TimeInStateTest, AllUidConcurrentTimesFailsOnInvalidBucket) {
    uint32_t uid = 0;
    {
        // Find an unused UID
        auto map = getUidsConcurrentTimes();
        ASSERT_TRUE(map.has_value());
        ASSERT_FALSE(map->empty());
        for (const auto &kv : *map) uid = std::max(uid, kv.first);
        ++uid;
    }
    android::base::unique_fd fd{
        bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_concurrent_times_map")};
    ASSERT_GE(fd, 0);
    uint32_t nCpus = get_nprocs_conf();
    uint32_t maxBucket = (nCpus - 1) / CPUS_PER_ENTRY;
    time_key_t key = {.uid = uid, .bucket = maxBucket + 1};
    std::vector<concurrent_val_t> vals(nCpus);
    ASSERT_FALSE(writeToMapEntry(fd, &key, vals.data(), BPF_NOEXIST));
    EXPECT_FALSE(getUidsConcurrentTimes().has_value());
    ASSERT_FALSE(deleteMapEntry(fd, &key));
}

TEST(TimeInStateTest, AllUidTimesConsistent) {
    auto tisMap = getUidsCpuFreqTimes();
    ASSERT_TRUE(tisMap.has_value());

    auto concurrentMap = getUidsConcurrentTimes();
    ASSERT_TRUE(concurrentMap.has_value());

    ASSERT_EQ(tisMap->size(), concurrentMap->size());
    for (const auto &kv : *tisMap) {
        uint32_t uid = kv.first;
        auto times = kv.second;
        ASSERT_NE(concurrentMap->find(uid), concurrentMap->end());

        auto concurrentTimes = (*concurrentMap)[uid];
        ASSERT_NO_FATAL_FAILURE(TestUidTimesConsistent(times, concurrentTimes));
    }
}

TEST(TimeInStateTest, RemoveUid) {
    uint32_t uid = 0;
    {
        // Find an unused UID
        auto times = getUidsCpuFreqTimes();
        ASSERT_TRUE(times.has_value());
        ASSERT_FALSE(times->empty());
        for (const auto &kv : *times) uid = std::max(uid, kv.first);
        ++uid;
    }
    {
        // Add a map entry for our fake UID by copying a real map entry
        android::base::unique_fd fd{
                bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_time_in_state_map")};
        ASSERT_GE(fd, 0);
        time_key_t k;
        ASSERT_FALSE(getFirstMapKey(fd, &k));
        std::vector<tis_val_t> vals(get_nprocs_conf());
        ASSERT_FALSE(findMapEntry(fd, &k, vals.data()));
        uint32_t copiedUid = k.uid;
        k.uid = uid;
        ASSERT_FALSE(writeToMapEntry(fd, &k, vals.data(), BPF_NOEXIST));

        android::base::unique_fd fd2{
                bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_concurrent_times_map")};
        k.uid = copiedUid;
        k.bucket = 0;
        std::vector<concurrent_val_t> cvals(get_nprocs_conf());
        ASSERT_FALSE(findMapEntry(fd2, &k, cvals.data()));
        k.uid = uid;
        ASSERT_FALSE(writeToMapEntry(fd2, &k, cvals.data(), BPF_NOEXIST));
    }
    auto times = getUidCpuFreqTimes(uid);
    ASSERT_TRUE(times.has_value());
    ASSERT_FALSE(times->empty());

    auto concurrentTimes = getUidConcurrentTimes(0);
    ASSERT_TRUE(concurrentTimes.has_value());
    ASSERT_FALSE(concurrentTimes->active.empty());
    ASSERT_FALSE(concurrentTimes->policy.empty());

    uint64_t sum = 0;
    for (size_t i = 0; i < times->size(); ++i) {
        for (auto x : (*times)[i]) sum += x;
    }
    ASSERT_GT(sum, (uint64_t)0);

    uint64_t activeSum = 0;
    for (size_t i = 0; i < concurrentTimes->active.size(); ++i) {
        activeSum += concurrentTimes->active[i];
    }
    ASSERT_GT(activeSum, (uint64_t)0);

    ASSERT_TRUE(clearUidTimes(uid));

    auto allTimes = getUidsCpuFreqTimes();
    ASSERT_TRUE(allTimes.has_value());
    ASSERT_FALSE(allTimes->empty());
    ASSERT_EQ(allTimes->find(uid), allTimes->end());

    auto allConcurrentTimes = getUidsConcurrentTimes();
    ASSERT_TRUE(allConcurrentTimes.has_value());
    ASSERT_FALSE(allConcurrentTimes->empty());
    ASSERT_EQ(allConcurrentTimes->find(uid), allConcurrentTimes->end());
}

TEST(TimeInStateTest, GetCpuFreqs) {
    auto freqs = getCpuFreqs();
    ASSERT_TRUE(freqs.has_value());

    auto times = getUidCpuFreqTimes(0);
    ASSERT_TRUE(times.has_value());

    ASSERT_EQ(freqs->size(), times->size());
    for (size_t i = 0; i < freqs->size(); ++i) EXPECT_EQ((*freqs)[i].size(), (*times)[i].size());
}

uint64_t timeNanos() {
    struct timespec spec;
    clock_gettime(CLOCK_MONOTONIC, &spec);
    return spec.tv_sec * 1000000000 + spec.tv_nsec;
}

// Keeps CPU busy with some number crunching
void useCpu() {
    long sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum *= i;
    }
}

sem_t pingsem, pongsem;

void *testThread(void *) {
    for (int i = 0; i < 10; i++) {
        sem_wait(&pingsem);
        useCpu();
        sem_post(&pongsem);
    }
    return nullptr;
}

TEST(TimeInStateTest, GetAggregatedTaskCpuFreqTimes) {
    uint64_t startTimeNs = timeNanos();

    sem_init(&pingsem, 0, 1);
    sem_init(&pongsem, 0, 0);

    pthread_t thread;
    ASSERT_EQ(pthread_create(&thread, NULL, &testThread, NULL), 0);

    // This process may have been running for some time, so when we start tracking
    // CPU time, the very first switch may include the accumulated time.
    // Yield the remainder of this timeslice to the newly created thread.
    sem_wait(&pongsem);
    sem_post(&pingsem);

    pid_t tgid = getpid();
    startTrackingProcessCpuTimes(tgid);

    pid_t tid = pthread_gettid_np(thread);
    startAggregatingTaskCpuTimes(tid, 42);

    // Play ping-pong with the other thread to ensure that both threads get
    // some CPU time.
    for (int i = 0; i < 9; i++) {
        sem_wait(&pongsem);
        useCpu();
        sem_post(&pingsem);
    }

    pthread_join(thread, NULL);

    std::optional<std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>>> optionalMap =
            getAggregatedTaskCpuFreqTimes(tgid, {0, 42});
    ASSERT_TRUE(optionalMap);

    std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>> map = *optionalMap;
    ASSERT_EQ(map.size(), 2u);

    uint64_t testDurationNs = timeNanos() - startTimeNs;
    for (auto pair : map) {
        uint16_t aggregationKey = pair.first;
        ASSERT_TRUE(aggregationKey == 0 || aggregationKey == 42);

        std::vector<std::vector<uint64_t>> timesInState = pair.second;
        uint64_t totalCpuTime = 0;
        for (size_t i = 0; i < timesInState.size(); i++) {
            for (size_t j = 0; j < timesInState[i].size(); j++) {
                totalCpuTime += timesInState[i][j];
            }
        }
        ASSERT_GT(totalCpuTime, 0ul);
        ASSERT_LE(totalCpuTime, testDurationNs);
    }
}

} // namespace bpf
} // namespace android
