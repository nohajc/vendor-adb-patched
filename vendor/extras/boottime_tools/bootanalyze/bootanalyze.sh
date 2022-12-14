#!/bin/bash

# Copyright (C) 2020 The Android Open Source Project
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

readme() {
    echo '
Analyze boot-time & bootchart
e.g.
ANDROID_BUILD_TOP="$PWD" \
CONFIG_YMAL="$ANDROID_BUILD_TOP/system/extras/boottime_tools/bootanalyze/config.yaml" \
    LOOPS=3 \
    RESULTS_DIR="$ANDROID_BUILD_TOP/bootAnalyzeResults" \
    $PWD/system/extras/boottime_tools/bootanalyze/bootanalyze.sh
'
    exit
}


if [[ -z $ANDROID_BUILD_TOP ]]; then
    echo 'Error: you need to specify ANDROID_BUILD_TOP'
    readme
fi
echo "ANDROID_BUILD_TOP=$ANDROID_BUILD_TOP"
SCRIPT_DIR="$ANDROID_BUILD_TOP/system/extras/boottime_tools/bootanalyze"


if [[ -z $CONFIG_YMAL ]]; then
	CONFIG_YMAL="$SCRIPT_DIR/config.yaml"
fi
echo "CONFIG_YMAL=$CONFIG_YMAL"


if [[ -z $RESULTS_DIR ]]; then
	RESULTS_DIR="$PWD/bootAnalyzeResults"
fi
echo "RESULTS_DIR=$RESULTS_DIR"
mkdir -p $RESULTS_DIR


adb shell 'touch /data/bootchart/enabled'

if [[ -z $LOOPS ]]; then
	LOOPS=1
fi
echo "Analyzing boot-time for LOOPS=$LOOPS"
START=1

SLEEP_SEC=30
for (( l=$START; l<=$LOOPS; l++ )); do
    echo -n "Loop: $l"
    SECONDS=0
    $SCRIPT_DIR/bootanalyze.py -c $CONFIG_YMAL -G 4M -r -b > "$RESULTS_DIR/boot$l.txt"
    echo "$SECONDS sec."
    cp /tmp/android-bootchart/bootchart.tgz "$RESULTS_DIR/bootchart$l.tgz"
    echo "Sleep for $SLEEP_SEC sec."
    sleep $SLEEP_SEC
done

echo
echo "Complete $LOOPS"