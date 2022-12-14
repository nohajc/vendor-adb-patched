# Binder for Trusty

This is the Trusty port of the libbinder library.
To build it, take the following steps:

* Check out copies of the Trusty and AOSP repositories.
* Apply the patches from the `trusty_binder` topic on both repositories.
* Build Trusty normally using `build.py`.
* Run the sample AIDL test for Trusty:
  ```shell
  $ ./build-root/.../run --headless --boot-test com.android.trusty.aidl.test
  ```

To run the Android-Trusty IPC test, do the following:

* Build AOSP for the `qemu_trusty_arm64-userdebug` target:
  ```shell
  $ lunch qemu_trusty_arm64-userdebug
  $ m
  ```
* In the Trusty directory, run the emulator with the newly built Android:
  ```shell
  $ ./build-root/.../run --android /path/to/aosp
  ```
* Using either `adb` or the shell inside the emulator itself, run the Trusty
  Binder test as root:
  ```shell
  # /data/nativetest64/vendor/trusty_binder_test/trusty_binder_test
  ```

## Running the AIDL compiler
For now, you will need to run the AIDL compiler manually to generate the C++
source code for Trusty clients and services. The general syntax is:
```shell
$ aidl --lang=cpp -o <output directory> -h <output header directory> <AIDL files...>
```

The compiler will emit some `.cpp` files in the output directory and their
corresponding `.h` files in the header directory.
