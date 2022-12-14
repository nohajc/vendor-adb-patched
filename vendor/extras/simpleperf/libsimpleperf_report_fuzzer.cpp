
#include <android-base/file.h>

#include "report_lib_interface.cpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  TemporaryFile tmpfile;
  android::base::WriteStringToFd(std::string(reinterpret_cast<const char*>(data), size),
                                 tmpfile.fd);
  ReportLib* report_lib = CreateReportLib();
  SetRecordFile(report_lib, tmpfile.path);
  while (true) {
    Sample* sample = GetNextSample(report_lib);
    if (sample == nullptr) {
      break;
    }
  }
  DestroyReportLib(report_lib);
  return 0;
}
