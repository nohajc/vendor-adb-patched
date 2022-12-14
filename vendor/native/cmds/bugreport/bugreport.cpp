/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

// Only prints a warning redirecting to bugreportz.
int main() {
    fprintf(stderr,
            "=============================================================================\n");
    fprintf(stderr, "WARNING: Flat (text file, non-zipped) bugreports are deprecated.\n");
    fprintf(stderr, "WARNING: Please generate zipped bugreports instead.\n");
    fprintf(stderr, "WARNING: On the host use: adb bugreport filename.zip\n");
    fprintf(stderr, "WARNING: On the device use: bugreportz\n");
    fprintf(stderr, "WARNING: bugreportz will output the filename to use with adb pull.\n");
    fprintf(stderr,
            "=============================================================================\n\n\n");

    return 0;
}
