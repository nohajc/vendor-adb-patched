# Simpleperf

This file is documentation for simpleperf maintainers.
There is also [user documentation](doc/README.md).

## Building new prebuilts

To snap the aosp-simpleperf-release branch to ToT AOSP main and kick off a
build, use [this coastguard
page](https://android-build.googleplex.com/coastguard/dashboard/5938649007521792/#/request/create)
and choose "aosp-simpleperf-release" from the "Branch" dropdown. Then click
"Submit build requests". You'll get emails keeping you up to date with the
progress of the snap and the build.

## Updating the prebuilts

Once you have the build id (a 7-digit number) and the build is complete, run the
update script from within the `system/extras/simpleperf` directory:
```
./scripts/update.py --bid 1234567 -vv
```

This will create a new change that you can `repo upload`, then approve and
submit as normal.
