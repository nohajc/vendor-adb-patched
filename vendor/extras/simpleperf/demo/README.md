# Examples of using simpleperf to profile Android applications

## Table of Contents

- [Examples of using simpleperf to profile Android applications](#examples-of-using-simpleperf-to-profile-android-applications)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Profile a Java application](#profile-a-java-application)
  - [Profile a Java/C++ application](#profile-a-javac-application)
  - [Profile a Kotlin application](#profile-a-kotlin-application)
- [Profile via app_api](#profile-via-app_api)

## Introduction

Simpleperf is a native profiler used on Android platform. It can be used to profile Android
applications. Its documentation is [here](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/doc/README.md).
Instructions of preparing your Android application for profiling are [here](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/doc/README.md#Android-application-profiling).
This directory is to show examples of using simpleperf to profile Android applications. The
meaning of each directory is as below:

    ../scripts/                  -- contain simpleperf binaries and scripts.
    SimpleperfExamplePureJava/   -- contains an Android Studio project using only Java code.
    SimpleperfExampleWithNative/ -- contains an Android Studio project using both Java and C++ code.
    SimpleperfExampleOfKotlin/   -- contains an Android Studio project using Kotlin code.
    CppApi/                      -- contains an Android Studio project using c++ app_api to record.
    JavaApi/                     -- contains an Android Studio project using Java app_api to record.

It can be downloaded as below:

```sh
$ git clone https://android.googlesource.com/platform/system/extras
$ cd extras/simpleperf/demo
```

The testing environment:

```
Android Studio 3.2
test device: Android O (Google Pixel 2)
test device: Android N (Google Nexus 6P)
Please make sure your device having Android version >= N.
```

## Profile a Java application

Android Studio project: SimpleExamplePureJava

steps:
1. Build and install the application:

```sh
# Open SimpleperfExamplesPureJava project with Android Studio,
# and build this project successfully, otherwise the `./gradlew` command below will fail.
$ cd SimpleperfExamplePureJava

# On windows, use "gradlew" instead.
$ ./gradlew clean assemble
$ adb install -r app/build/outputs/apk/app-profiling.apk
```

2. Record profiling data:

```sh
$ cd ../../scripts/
# app_profiler.py collects profiling data in perf.data, and binaries on device in binary_cache/.
$ python app_profiler.py -p com.example.simpleperf.simpleperfexamplepurejava
```

3. Show profiling data:

```sh
# report_html.py generates profiling result in report.html.
$ python report_html.py --add_source_code --source_dirs ../demo --add_disassembly
```

## Profile a Java/C++ application

Android Studio project: SimpleExampleWithNative

steps:
1. Build and install the application:

```sh
# Open SimpleperfExamplesWithNative project with Android Studio,
# and build this project sucessfully, otherwise the `./gradlew` command below will fail.
$ cd SimpleperfExampleWithNative

# On windows, use "gradlew" instead.
$ ./gradlew clean assemble
$ adb install -r app/build/outputs/apk/profiling/app-profiling.apk
```

2. Record profiling data:

```sh
$ cd ../../scripts/
# app_profiler.py collects profiling data in perf.data, and binaries on device in binary_cache/.
$ python app_profiler.py -p com.example.simpleperf.simpleperfexamplewithnative
```

3. Show profiling data:

```sh
# report_html.py generates profiling result in report.html.
$ python report_html.py --add_source_code --source_dirs ../demo --add_disassembly
```

## Profile a Kotlin application

Android Studio project: SimpleExampleOfKotlin

steps:
1. Build and install the application:

```sh
# Open SimpleperfExamplesOfKotlin project with Android Studio,
# and build this project sucessfully, otherwise the `./gradlew` command below will fail.
$ cd SimpleperfExampleOfKotlin

# On windows, use "gradlew" instead.
$ ./gradlew clean assemble
$ adb install -r app/build/outputs/apk/profiling/app-profiling.apk
```

2. Record profiling data:

```sh
$ cd ../../scripts/
# app_profiler.py collects profiling data in perf.data, and binaries on device in binary_cache/.
$ python app_profiler.py -p com.example.simpleperf.simpleperfexampleofkotlin
```

3. Show profiling data:

```sh
# report_html.py generates profiling result in report.html.
$ python report_html.py --add_source_code --source_dirs ../demo --add_disassembly
```

# Profile via app_api

Android Studio project: CppApi and JavaApi

steps:
1. Build and install the application:

```sh
# Open CppApi project with Android Studio,
# and build this project sucessfully, otherwise the `./gradlew` command below will fail.
$ cd CppApi

# On windows, use "gradlew" instead.
$ ./gradlew clean assemble
$ adb install -r app/build/outputs/apk/debug/app-debug.apk
```

2. Prepare recording environment.

```sh
$ cd ../../scripts/
$ python api_profiler.py prepare
```

3. Run the CppApi app.

```sh
# launch the app via cmdline, can also launch it on device.
# A profiling file is generated each time running the app.
$ adb shell am start simpleperf.demo.cpp_api/.MainActivity
```

4. Collect profiling data.

```sh
$ python api_profiler.py collect -p simpleperf.demo.cpp_api
```

5. Report profiling data.

```sh
$ python report_html.py -i simpleperf_data/* --aggregate-by-thread-name
```
