# Fuzzer for libcmd_fuzzer

## Plugin Design Considerations
The fuzzer plugin for libcmd is designed based on the understanding of the library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libcmd supports the following parameters:
1. In (parameter name: `in`)
2. Out (parameter name: `out`)
3. Err (parameter name: `err`)
4. Run Mode (parameter name: `runMode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `in` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider|
| `out` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider|
| `err` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider|
| `runMode` | 1.`RunMode::kStandalone` 2. `RunMode::kLibrary` | Value chosen from valid values using FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the cmd module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build cmd_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) cmd_fuzzer
```
#### Steps to run
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/cmd_fuzzer/cmd_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
