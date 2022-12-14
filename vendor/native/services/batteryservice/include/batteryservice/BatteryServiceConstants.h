#ifndef AIDL_android_hardware_health_V2_EXPORTED_CONSTANTS_H_
#define AIDL_android_hardware_health_V2_EXPORTED_CONSTANTS_H_

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BATTERY_STATUS_UNKNOWN = 1,
    BATTERY_STATUS_CHARGING = 2,
    BATTERY_STATUS_DISCHARGING = 3,
    BATTERY_STATUS_NOT_CHARGING = 4,
    BATTERY_STATUS_FULL = 5,
};

// must be kept in sync with definitions in
// hardware/interfaces/health/aidl/android/hardware/health/BatteryHealth.aidl
enum {
    BATTERY_HEALTH_UNKNOWN = 1,
    BATTERY_HEALTH_GOOD = 2,
    BATTERY_HEALTH_OVERHEAT = 3,
    BATTERY_HEALTH_DEAD = 4,
    BATTERY_HEALTH_OVER_VOLTAGE = 5,
    BATTERY_HEALTH_UNSPECIFIED_FAILURE = 6,
    BATTERY_HEALTH_COLD = 7,
    BATTERY_HEALTH_FAIR = 8,
    BATTERY_HEALTH_NOT_AVAILABLE = 11,
    BATTERY_HEALTH_INCONSISTENT = 12,
};

// must be kept in sync with definitions in
// hardware/interfaces/health/aidl/android/hardware/health/BatteryChargingState.aidl
enum {
    BATTERY_STATUS_NORMAL = 1,
    BATTERY_STATUS_TOO_COLD = 2,
    BATTERY_STATUS_TOO_HOT = 3,
    BATTERY_STATUS_LONG_LIFE = 4,
    BATTERY_STATUS_ADAPTIVE = 5,
};

#ifdef __cplusplus
}
#endif

#endif  // AIDL_android_hardware_health_V2_EXPORTED_CONSTANTS_H_
