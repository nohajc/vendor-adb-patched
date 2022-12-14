/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef _LIBINPUT_INPUT_DEVICE_H
#define _LIBINPUT_INPUT_DEVICE_H

#include <android/sensor.h>
#include <input/Input.h>
#include <input/KeyCharacterMap.h>
#include <unordered_map>
#include <vector>

namespace android {

/*
 * Identifies a device.
 */
struct InputDeviceIdentifier {
    inline InputDeviceIdentifier() :
            bus(0), vendor(0), product(0), version(0) {
    }

    // Information provided by the kernel.
    std::string name;
    std::string location;
    std::string uniqueId;
    uint16_t bus;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;

    // A composite input device descriptor string that uniquely identifies the device
    // even across reboots or reconnections.  The value of this field is used by
    // upper layers of the input system to associate settings with individual devices.
    // It is hashed from whatever kernel provided information is available.
    // Ideally, the way this value is computed should not change between Android releases
    // because that would invalidate persistent settings that rely on it.
    std::string descriptor;

    // A value added to uniquely identify a device in the absence of a unique id. This
    // is intended to be a minimum way to distinguish from other active devices and may
    // reuse values that are not associated with an input anymore.
    uint16_t nonce;

    /**
     * Return InputDeviceIdentifier.name that has been adjusted as follows:
     *     - all characters besides alphanumerics, dash,
     *       and underscore have been replaced with underscores.
     * This helps in situations where a file that matches the device name is needed,
     * while conforming to the filename limitations.
     */
    std::string getCanonicalName() const;
};

/* Types of input device sensors. Keep sync with core/java/android/hardware/Sensor.java */
enum class InputDeviceSensorType : int32_t {
    ACCELEROMETER = ASENSOR_TYPE_ACCELEROMETER,
    MAGNETIC_FIELD = ASENSOR_TYPE_MAGNETIC_FIELD,
    ORIENTATION = 3,
    GYROSCOPE = ASENSOR_TYPE_GYROSCOPE,
    LIGHT = ASENSOR_TYPE_LIGHT,
    PRESSURE = ASENSOR_TYPE_PRESSURE,
    TEMPERATURE = 7,
    PROXIMITY = ASENSOR_TYPE_PROXIMITY,
    GRAVITY = ASENSOR_TYPE_GRAVITY,
    LINEAR_ACCELERATION = ASENSOR_TYPE_LINEAR_ACCELERATION,
    ROTATION_VECTOR = ASENSOR_TYPE_ROTATION_VECTOR,
    RELATIVE_HUMIDITY = ASENSOR_TYPE_RELATIVE_HUMIDITY,
    AMBIENT_TEMPERATURE = ASENSOR_TYPE_AMBIENT_TEMPERATURE,
    MAGNETIC_FIELD_UNCALIBRATED = ASENSOR_TYPE_MAGNETIC_FIELD_UNCALIBRATED,
    GAME_ROTATION_VECTOR = ASENSOR_TYPE_GAME_ROTATION_VECTOR,
    GYROSCOPE_UNCALIBRATED = ASENSOR_TYPE_GYROSCOPE_UNCALIBRATED,
    SIGNIFICANT_MOTION = ASENSOR_TYPE_SIGNIFICANT_MOTION,

    ftl_first = ACCELEROMETER,
    ftl_last = SIGNIFICANT_MOTION
};

enum class InputDeviceSensorAccuracy : int32_t {
    ACCURACY_NONE = 0,
    ACCURACY_LOW = 1,
    ACCURACY_MEDIUM = 2,
    ACCURACY_HIGH = 3,
};

enum class InputDeviceSensorReportingMode : int32_t {
    CONTINUOUS = 0,
    ON_CHANGE = 1,
    ONE_SHOT = 2,
    SPECIAL_TRIGGER = 3,
};

enum class InputDeviceLightType : int32_t {
    MONO = 0,
    PLAYER_ID = 1,
    RGB = 2,
    MULTI_COLOR = 3,

    ftl_last = MULTI_COLOR
};

struct InputDeviceSensorInfo {
    explicit InputDeviceSensorInfo(std::string name, std::string vendor, int32_t version,
                                   InputDeviceSensorType type, InputDeviceSensorAccuracy accuracy,
                                   float maxRange, float resolution, float power, int32_t minDelay,
                                   int32_t fifoReservedEventCount, int32_t fifoMaxEventCount,
                                   std::string stringType, int32_t maxDelay, int32_t flags,
                                   int32_t id)
          : name(name),
            vendor(vendor),
            version(version),
            type(type),
            accuracy(accuracy),
            maxRange(maxRange),
            resolution(resolution),
            power(power),
            minDelay(minDelay),
            fifoReservedEventCount(fifoReservedEventCount),
            fifoMaxEventCount(fifoMaxEventCount),
            stringType(stringType),
            maxDelay(maxDelay),
            flags(flags),
            id(id) {}
    // Name string of the sensor.
    std::string name;
    // Vendor string of this sensor.
    std::string vendor;
    // Version of the sensor's module.
    int32_t version;
    // Generic type of this sensor.
    InputDeviceSensorType type;
    // The current accuracy of sensor event.
    InputDeviceSensorAccuracy accuracy;
    // Maximum range of the sensor in the sensor's unit.
    float maxRange;
    // Resolution of the sensor in the sensor's unit.
    float resolution;
    // The power in mA used by this sensor while in use.
    float power;
    // The minimum delay allowed between two events in microsecond or zero if this sensor only
    // returns a value when the data it's measuring changes.
    int32_t minDelay;
    // Number of events reserved for this sensor in the batch mode FIFO.
    int32_t fifoReservedEventCount;
    // Maximum number of events of this sensor that could be batched.
    int32_t fifoMaxEventCount;
    // The type of this sensor as a string.
    std::string stringType;
    // The delay between two sensor events corresponding to the lowest frequency that this sensor
    // supports.
    int32_t maxDelay;
    // Sensor flags
    int32_t flags;
    // Sensor id, same as the input device ID it belongs to.
    int32_t id;
};

struct InputDeviceLightInfo {
    explicit InputDeviceLightInfo(std::string name, int32_t id, InputDeviceLightType type,
                                  int32_t ordinal)
          : name(name), id(id), type(type), ordinal(ordinal) {}
    // Name string of the light.
    std::string name;
    // Light id
    int32_t id;
    // Type of the light.
    InputDeviceLightType type;
    // Ordinal of the light
    int32_t ordinal;
};

struct InputDeviceBatteryInfo {
    explicit InputDeviceBatteryInfo(std::string name, int32_t id) : name(name), id(id) {}
    // Name string of the battery.
    std::string name;
    // Battery id
    int32_t id;
};

/*
 * Describes the characteristics and capabilities of an input device.
 */
class InputDeviceInfo {
public:
    InputDeviceInfo();
    InputDeviceInfo(const InputDeviceInfo& other);
    ~InputDeviceInfo();

    struct MotionRange {
        int32_t axis;
        uint32_t source;
        float min;
        float max;
        float flat;
        float fuzz;
        float resolution;
    };

    void initialize(int32_t id, int32_t generation, int32_t controllerNumber,
            const InputDeviceIdentifier& identifier, const std::string& alias, bool isExternal,
            bool hasMic);

    inline int32_t getId() const { return mId; }
    inline int32_t getControllerNumber() const { return mControllerNumber; }
    inline int32_t getGeneration() const { return mGeneration; }
    inline const InputDeviceIdentifier& getIdentifier() const { return mIdentifier; }
    inline const std::string& getAlias() const { return mAlias; }
    inline const std::string& getDisplayName() const {
        return mAlias.empty() ? mIdentifier.name : mAlias;
    }
    inline bool isExternal() const { return mIsExternal; }
    inline bool hasMic() const { return mHasMic; }
    inline uint32_t getSources() const { return mSources; }

    const MotionRange* getMotionRange(int32_t axis, uint32_t source) const;

    void addSource(uint32_t source);
    void addMotionRange(int32_t axis, uint32_t source,
            float min, float max, float flat, float fuzz, float resolution);
    void addMotionRange(const MotionRange& range);
    void addSensorInfo(const InputDeviceSensorInfo& info);
    void addBatteryInfo(const InputDeviceBatteryInfo& info);
    void addLightInfo(const InputDeviceLightInfo& info);

    void setKeyboardType(int32_t keyboardType);
    inline int32_t getKeyboardType() const { return mKeyboardType; }

    inline void setKeyCharacterMap(const std::shared_ptr<KeyCharacterMap> value) {
        mKeyCharacterMap = value;
    }

    inline const std::shared_ptr<KeyCharacterMap> getKeyCharacterMap() const {
        return mKeyCharacterMap;
    }

    inline void setVibrator(bool hasVibrator) { mHasVibrator = hasVibrator; }
    inline bool hasVibrator() const { return mHasVibrator; }

    inline void setHasBattery(bool hasBattery) { mHasBattery = hasBattery; }
    inline bool hasBattery() const { return mHasBattery; }

    inline void setButtonUnderPad(bool hasButton) { mHasButtonUnderPad = hasButton; }
    inline bool hasButtonUnderPad() const { return mHasButtonUnderPad; }

    inline void setHasSensor(bool hasSensor) { mHasSensor = hasSensor; }
    inline bool hasSensor() const { return mHasSensor; }

    inline const std::vector<MotionRange>& getMotionRanges() const {
        return mMotionRanges;
    }

    std::vector<InputDeviceSensorInfo> getSensors();

    std::vector<InputDeviceLightInfo> getLights();

private:
    int32_t mId;
    int32_t mGeneration;
    int32_t mControllerNumber;
    InputDeviceIdentifier mIdentifier;
    std::string mAlias;
    bool mIsExternal;
    bool mHasMic;
    uint32_t mSources;
    int32_t mKeyboardType;
    std::shared_ptr<KeyCharacterMap> mKeyCharacterMap;
    bool mHasVibrator;
    bool mHasBattery;
    bool mHasButtonUnderPad;
    bool mHasSensor;

    std::vector<MotionRange> mMotionRanges;
    std::unordered_map<InputDeviceSensorType, InputDeviceSensorInfo> mSensors;
    /* Map from light ID to light info */
    std::unordered_map<int32_t, InputDeviceLightInfo> mLights;
    /* Map from battery ID to battery info */
    std::unordered_map<int32_t, InputDeviceBatteryInfo> mBatteries;
};

/* Types of input device configuration files. */
enum class InputDeviceConfigurationFileType : int32_t {
    CONFIGURATION = 0,     /* .idc file */
    KEY_LAYOUT = 1,        /* .kl file */
    KEY_CHARACTER_MAP = 2, /* .kcm file */
};

/*
 * Gets the path of an input device configuration file, if one is available.
 * Considers both system provided and user installed configuration files.
 * The optional suffix is appended to the end of the file name (before the
 * extension).
 *
 * The device identifier is used to construct several default configuration file
 * names to try based on the device name, vendor, product, and version.
 *
 * Returns an empty string if not found.
 */
extern std::string getInputDeviceConfigurationFilePathByDeviceIdentifier(
        const InputDeviceIdentifier& deviceIdentifier, InputDeviceConfigurationFileType type,
        const char* suffix = "");

/*
 * Gets the path of an input device configuration file, if one is available.
 * Considers both system provided and user installed configuration files.
 *
 * The name is case-sensitive and is used to construct the filename to resolve.
 * All characters except 'a'-'z', 'A'-'Z', '0'-'9', '-', and '_' are replaced by underscores.
 *
 * Returns an empty string if not found.
 */
extern std::string getInputDeviceConfigurationFilePathByName(
        const std::string& name, InputDeviceConfigurationFileType type);

enum ReservedInputDeviceId : int32_t {
    // Device id of a special "virtual" keyboard that is always present.
    VIRTUAL_KEYBOARD_ID = -1,
    // Device id of the "built-in" keyboard if there is one.
    BUILT_IN_KEYBOARD_ID = 0,
    // First device id available for dynamic devices
    END_RESERVED_ID = 1,
};

} // namespace android

#endif // _LIBINPUT_INPUT_DEVICE_H
