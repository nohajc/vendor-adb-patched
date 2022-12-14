
#include <android-base/file.h>

#include "command.h"
#include "report_lib_interface.cpp"
#include "test_util.h"

using namespace simpleperf;

namespace {

void TestReportLib(const char* record_file) {
  ReportLib* report_lib = CreateReportLib();
  SetRecordFile(report_lib, record_file);
  while (true) {
    Sample* sample = GetNextSample(report_lib);
    if (sample == nullptr) {
      break;
    }
  }
  DestroyReportLib(report_lib);
}

void TestDumpCmd(const char* record_file) {
  std::unique_ptr<Command> dump_cmd = CreateCommandInstance("dump");
  CaptureStdout capture;
  capture.Start();
  dump_cmd->Run({"-i", record_file, "--dump-etm", "raw,packet,element"});
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  TemporaryFile tmpfile;
  android::base::WriteFully(tmpfile.fd, data, size);
  TestReportLib(tmpfile.path);
  TestDumpCmd(tmpfile.path);
  return 0;
}
