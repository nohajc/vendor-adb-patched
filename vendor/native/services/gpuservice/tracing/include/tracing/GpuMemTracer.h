/*
 * Copyright 2020 The Android Open Source Project
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

#include <perfetto/tracing.h>

#include <mutex>

namespace perfetto::protos {
class TracePacket;
}

namespace android {

class GpuMem;

class GpuMemTracer {
public:
    class GpuMemDataSource : public perfetto::DataSource<GpuMemDataSource> {
        virtual void OnSetup(const SetupArgs&) override{};
        virtual void OnStart(const StartArgs&) override {
            std::unique_lock<std::mutex> lock(GpuMemTracer::sTraceMutex);
            sTraceStarted = true;
            sCondition.notify_all();
        }
        virtual void OnStop(const StopArgs&) override{};
    };

    ~GpuMemTracer() = default;

    // Sets up the perfetto tracing backend and data source.
    void initialize(std::shared_ptr<GpuMem>);
    // Registers the data source with the perfetto backend. Called as part of initialize()
    // and should not be called manually outside of tests. Public to allow for substituting a
    // perfetto::kInProcessBackend in tests.
    void registerDataSource();

    // TODO(b/175904796): Refactor gpuservice lib to include perfetto lib and move the test
    // functions into the unittests.
    // Functions only used for testing with in-process backend. These functions require the static
    // perfetto lib to be linked. If the tests have a perfetto linked, while libgpumemtracer.so also
    // has one linked, they will both use different static states maintained in perfetto. Since the
    // static perfetto states are not shared, tracing sessions created in the unit test are not
    // recognized by GpuMemTracer. As a result, we cannot use any of the perfetto functions from
    // this class, which defeats the purpose of the unit test. To solve this, we restrict all
    // tracing functionality to this class, while the unit test validates the data.
    // Sets up the perfetto in-process backend and calls into registerDataSource.
    void initializeForTest(std::shared_ptr<GpuMem>);
    // Creates a tracing session with in process backend, for testing.
    std::unique_ptr<perfetto::TracingSession> getTracingSessionForTest();
    // Read and filter the gpu memory packets from the created trace.
    std::vector<perfetto::protos::TracePacket> readGpuMemTotalPacketsForTestBlocking(
            perfetto::TracingSession* tracingSession);

    static constexpr char kGpuMemDataSource[] = "android.gpu.memory";
    static std::condition_variable sCondition;
    static std::mutex sTraceMutex;
    static bool sTraceStarted;

private:
    // Friend class for testing
    friend class GpuMemTracerTest;

    void threadLoop(bool infiniteLoop);
    void traceInitialCounters();
    std::shared_ptr<GpuMem> mGpuMem;
    // Count of how many tracer threads are currently active. Useful for testing.
    std::atomic<int32_t> tracerThreadCount = 0;
};

} // namespace android
