#!/system/bin/sh

#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This script will run as an pre-checkpointing cleanup for mounting f2fs
# with checkpoint=disable, so that the first mount after the reboot will
# be faster. It is unnecessary to run if the device does not use userdata
# checkpointing on F2FS.

# TARGET_SLOT="${1}"
STATUS_FD="${2}"

SLEEP=5
TIME=0
MAX_TIME=1200

# We only need to run this if we're using f2fs
if [ ! -f /dev/sys/fs/by-name/userdata/gc_urgent ]; then
  exit 0
fi

# Ideally we want to track unusable, as it directly measures what we
# care about. If it's not present, dirty_segments is the best proxy.
if [ -f /dev/sys/fs/by-name/userdata/unusable ]; then
  UNUSABLE=1
  METRIC="unusable blocks"
  THRESHOLD=25000
  read START < /dev/sys/fs/by-name/userdata/unusable
else
  METRIC="dirty segments"
  THRESHOLD=200
  read START < /dev/sys/fs/by-name/userdata/dirty_segments
fi

log -pi -t checkpoint_gc Turning on GC for userdata
echo 2 > /dev/sys/fs/by-name/userdata/gc_urgent || exit 1


CURRENT=${START}
TODO=$((${START}-${THRESHOLD}))
while [ ${CURRENT} -gt ${THRESHOLD} ]; do
  log -pi -t checkpoint_gc ${METRIC}:${CURRENT} \(threshold:${THRESHOLD}\)
  PROGRESS=`echo "(${START}-${CURRENT})/${TODO}"|bc -l`
  if [[ $PROGRESS == -* ]]; then
      PROGRESS=0
  fi
  print -u${STATUS_FD} "global_progress ${PROGRESS}"
  if [ ${UNUSABLE} -eq 1 ]; then
    read CURRENT < /dev/sys/fs/by-name/userdata/unusable
  else
    read CURRENT < /dev/sys/fs/by-name/userdata/dirty_segments
  fi
  sleep ${SLEEP}
  TIME=$((${TIME}+${SLEEP}))
  if [ ${TIME} -gt ${MAX_TIME} ]; then
    log -pi -t checkpoint_gc Timed out with gc threshold not met.
    break
  fi
  # In case someone turns it off behind our back
  echo 2 > /dev/sys/fs/by-name/userdata/gc_urgent
done

# It could be a while before the system reboots for the update...
# Leaving on low level GC can help ensure the boot for ota is faster
# If powerhints decides to turn it off, we'll just rely on normal GC
log -pi -t checkpoint_gc Leaving on low GC for userdata
echo 2 > /dev/sys/fs/by-name/userdata/gc_urgent
sync

print -u${STATUS_FD} "global_progress 1.0"
exit 0
