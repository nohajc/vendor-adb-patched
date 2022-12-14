# Binder for Trusty

This is the Trusty port of the libbinder library.
To build it, first you will need a checkout of the Trusty tree:
```shell
$ mkdir /path/to/trusty
$ cd /path/to/trusty
$ repo init -u https://android.googlesource.com/trusty/manifest -b master
$ repo sync -j$(nproc) -c --no-tags
```

After the checkout is complete, you can use the `build.py` script for both
building and testing Trusty. For a quick build without any tests, run:
```shell
$ ./trusty/vendor/google/aosp/scripts/build.py generic-arm64-test-debug
```
This will build the smaller `generic-arm64-test-debug` project which
does not run any tests.

The qemu-generic-arm64-test-debug` project includes the QEMU emulator and
a full Trusty test suite, including a set of libbinder tests.
To run the latter, use the command:
```shell
$ ./trusty/vendor/google/aosp/scripts/build.py \
    --test "boot-test:com.android.trusty.binder.test" \
    qemu-generic-arm64-test-debug
```

## Building AIDL files on Trusty
To compile AIDL interfaces into Trusty libraries, include the `make/aidl.mk`
in your `rules.mk` file, e.g.:
```
LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDLS := \
        $(LOCAL_DIR)/IFoo.aidl \

include make/aidl.mk
```

## Examples
The Trusty tree contains some sample test apps at
`trusty/user/app/sample/binder-test`.
