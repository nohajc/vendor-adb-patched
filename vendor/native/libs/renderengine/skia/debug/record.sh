# This script captures MSKP files from RenderEngine in a connected device.
# this only functions when RenderEngine uses the Skia backend.
# it triggers code in SkiaCapture.cpp.

# for a newly flashed device, perform first time steps with
# record.sh rootandsetup

# record all frames that RenderEngine handles over the span of 2 seconds.
# record.sh 2000

if [ -z "$1" ]; then
    printf 'Usage:\n    record.sh rootandsetup\n'
    printf '    record.sh MILLISECONDS\n\n'
    exit 1
elif [ "$1" == "rootandsetup" ]; then
  # first time use requires these changes
  adb root
  adb shell setenforce 0
  adb shell setprop debug.renderengine.backend "skiaglthreaded"
  adb shell stop
  adb shell start
  exit 1;
fi

check_permission() {
    adb shell getenforce
}

mode=$(check_permission)

if [ "$mode" != "Permissive" ]; then
   echo "Cannot write to disk from RenderEngine. run 'record.sh rootandsetup'"
   exit 5
fi

# record frames for some number of milliseconds.
adb shell setprop debug.renderengine.capture_skia_ms $1

# give the device time to both record, and starting writing the file.
# Total time needed to write the file depends on how much data was recorded.
# the loop at the end waits for this.
sleep $(($1 / 1000 + 4));

# There is no guarantee that at least one frame passed through renderengine during that time
# but as far as I know it always at least writes a 0-byte file with a new name, unless it crashes
# the process it is recording.
# /data/user/re_skiacapture_56204430551705.mskp

spin() {
    case "$spin" in
         1) printf '\b|';;
         2) printf '\b\\';;
         3) printf '\b-';;
         *) printf '\b/';;
    esac
    spin=$(( ( ${spin:-0} + 1 ) % 4 ))
    sleep $1
}

local_path=~/Downloads/

get_filename() {
    adb shell getprop debug.renderengine.capture_filename
}

remote_path=""
counter=0 # used to check only 1/sec though we update spinner 20/sec
while [ -z $remote_path ] ; do
    spin 0.05
    counter=$(( $counter+1 ))
    if ! (( $counter % 20)) ; then
        remote_path=$(get_filename)
    fi
done
printf '\b'

printf "MSKP file serialized to: $remote_path\n"

adb_pull_cmd="adb pull $remote_path $local_path"
echo $adb_pull_cmd
$adb_pull_cmd

adb shell rm "$remote_path"
printf 'SKP saved to %s\n\n' "$local_path"
