/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#error Do not rely on global include files. All Android cc_* programs are given access to \
    include_dirs for frameworks/native/include via global configuration, but this is legacy \
    configuration. Instead, you should have a direct dependency on libbinder OR one of your \
    dependencies should re-export libbinder headers with export_shared_lib_headers.
