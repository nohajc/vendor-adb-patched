# Fuzzers for SurfaceFlinger
## Table of contents
+ [SurfaceFlinger](#SurfaceFlinger)
+ [DisplayHardware](#DisplayHardware)
+ [Scheduler](#Scheduler)
+ [Layer](#Layer)

# <a name="SurfaceFlinger"></a> Fuzzer for SurfaceFlinger

SurfaceFlinger supports the following data sources:
1. Pixel Formats (parameter name: `defaultCompositionPixelFormat`)
2. Data Spaces (parameter name: `defaultCompositionDataspace`)
3. Rotations (parameter name: `internalDisplayOrientation`)
3. Surface composer tags (parameter name: `onTransact`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) surfaceflinger_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/surfaceflinger_fuzzer/surfaceflinger_fuzzer
```

# <a name="DisplayHardware"></a> Fuzzer for DisplayHardware

DisplayHardware supports the following parameters:
1. Hal Capability (parameter name: `hasCapability`)
2. Hal BlendMode (parameter name: `setBlendMode`)
3. Hal Composition (parameter name: `setCompositionType`)
4. Hal Display Capability (parameter name: `hasDisplayCapability`)
5. Composition Types (parameter name: `prepareFrame`)
6. Color Modes (parameter name: `setActiveColorMode`)
7. Render Intents (parameter name: `setActiveColorMode`)
8. Power Modes (parameter name: `setPowerMode`)
9. Content Types (parameter name: `setContentType`)
10. Data Space (parameter name: `setDataspace`)
11. Transforms (parameter name: `setLayerTransform`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) surfaceflinger_displayhardware_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/surfaceflinger_displayhardware_fuzzer/surfaceflinger_displayhardware_fuzzer
```

# <a name="Scheduler"></a> Fuzzer for Scheduler

Scheduler supports the following parameters:
1. VSync Periods (parameter name: `lowFpsPeriod`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) surfaceflinger_scheduler_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/surfaceflinger_scheduler_fuzzer/surfaceflinger_scheduler_fuzzer
```

# <a name="Layer"></a> Fuzzer for Layer

Layer supports the following parameters:
1. Display Connection Types (parameter name: `fakeDisplay`)
2. State Sets (parameter name: `traverseInZOrder`)
3. State Subsets (parameter name: `prepareCompositionState`)
4. Disconnect modes (parameter name: `disconnect`)
5. Data Spaces (parameter name: `setDataspace`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) surfaceflinger_layer_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/surfaceflinger_layer_fuzzer/surfaceflinger_layer_fuzzer
```
