This library turns on recording of skia commands in SkiaGL version of the RE.
The debug property defines number of milliseconds for the recording to take place.
A non zero value turns on the recording. The recording will stop after MS specified.
To reset the recording, set the capture_skia_ms flag to a new time. When recording
is finished, the capture_skia_ms flag will be set to 0 to avoid circular recording.

In order to allow the process to write files onto the device run:
adb shell setenforce 0

To start recording run:
adb shell setprop debug.renderengine.capture_skia_ms 1000

File will be stored in the /data/user/ directory on the device:
adb shell ls -al /data/user/

To retrieve the data from the device:
adb pull /data/user/re_skiacapture_<timestamp>.mskp
