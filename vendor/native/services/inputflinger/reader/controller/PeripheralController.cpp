/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <locale>
#include <regex>

#include <ftl/enum.h>

#include "../Macros.h"
#include "PeripheralController.h"

// Log detailed debug messages about input device lights.
static constexpr bool DEBUG_LIGHT_DETAILS = false;

namespace android {

static inline int32_t getAlpha(int32_t color) {
    return (color >> 24) & 0xff;
}

static inline int32_t getRed(int32_t color) {
    return (color >> 16) & 0xff;
}

static inline int32_t getGreen(int32_t color) {
    return (color >> 8) & 0xff;
}

static inline int32_t getBlue(int32_t color) {
    return color & 0xff;
}

static inline int32_t toArgb(int32_t brightness, int32_t red, int32_t green, int32_t blue) {
    return (brightness & 0xff) << 24 | (red & 0xff) << 16 | (green & 0xff) << 8 | (blue & 0xff);
}

/**
 * Input controller owned by InputReader device, implements the native API for querying input
 * lights, getting and setting the lights brightness and color, by interacting with EventHub
 * devices.
 */
PeripheralController::PeripheralController(InputDeviceContext& deviceContext)
      : mDeviceContext(deviceContext) {
    configureBattries();
    configureLights();
}

PeripheralController::~PeripheralController() {}

std::optional<std::int32_t> PeripheralController::Light::getRawLightBrightness(int32_t rawLightId) {
    std::optional<RawLightInfo> rawInfoOpt = context.getRawLightInfo(rawLightId);
    if (!rawInfoOpt.has_value()) {
        return std::nullopt;
    }
    std::optional<int32_t> brightnessOpt = context.getLightBrightness(rawLightId);
    if (!brightnessOpt.has_value()) {
        return std::nullopt;
    }
    int brightness = brightnessOpt.value();

    // If the light node doesn't have max brightness, use the default max brightness.
    int rawMaxBrightness = rawInfoOpt->maxBrightness.value_or(MAX_BRIGHTNESS);
    float ratio = MAX_BRIGHTNESS / rawMaxBrightness;
    // Scale the returned brightness in [0, rawMaxBrightness] to [0, 255]
    if (rawMaxBrightness != MAX_BRIGHTNESS) {
        brightness = brightness * ratio;
    }
    if (DEBUG_LIGHT_DETAILS) {
        ALOGD("getRawLightBrightness rawLightId %d brightness 0x%x ratio %.2f", rawLightId,
              brightness, ratio);
    }
    return brightness;
}

void PeripheralController::Light::setRawLightBrightness(int32_t rawLightId, int32_t brightness) {
    std::optional<RawLightInfo> rawInfo = context.getRawLightInfo(rawLightId);
    if (!rawInfo.has_value()) {
        return;
    }
    // If the light node doesn't have max brightness, use the default max brightness.
    int rawMaxBrightness = rawInfo->maxBrightness.value_or(MAX_BRIGHTNESS);
    float ratio = MAX_BRIGHTNESS / rawMaxBrightness;
    // Scale the requested brightness in [0, 255] to [0, rawMaxBrightness]
    if (rawMaxBrightness != MAX_BRIGHTNESS) {
        brightness = ceil(brightness / ratio);
    }
    if (DEBUG_LIGHT_DETAILS) {
        ALOGD("setRawLightBrightness rawLightId %d brightness 0x%x ratio %.2f", rawLightId,
              brightness, ratio);
    }
    context.setLightBrightness(rawLightId, brightness);
}

bool PeripheralController::MonoLight::setLightColor(int32_t color) {
    int32_t brightness = getAlpha(color);
    setRawLightBrightness(rawId, brightness);

    return true;
}

bool PeripheralController::RgbLight::setLightColor(int32_t color) {
    // Compose color value as per:
    // https://developer.android.com/reference/android/graphics/Color?hl=en
    // int color = (A & 0xff) << 24 | (R & 0xff) << 16 | (G & 0xff) << 8 | (B & 0xff);
    // The alpha component is used to scale the R,G,B leds brightness, with the ratio to
    // MAX_BRIGHTNESS.
    brightness = getAlpha(color);
    int32_t red = 0;
    int32_t green = 0;
    int32_t blue = 0;
    if (brightness > 0) {
        float ratio = MAX_BRIGHTNESS / brightness;
        red = ceil(getRed(color) / ratio);
        green = ceil(getGreen(color) / ratio);
        blue = ceil(getBlue(color) / ratio);
    }
    setRawLightBrightness(rawRgbIds.at(LightColor::RED), red);
    setRawLightBrightness(rawRgbIds.at(LightColor::GREEN), green);
    setRawLightBrightness(rawRgbIds.at(LightColor::BLUE), blue);
    if (rawGlobalId.has_value()) {
        setRawLightBrightness(rawGlobalId.value(), brightness);
    }

    return true;
}

bool PeripheralController::MultiColorLight::setLightColor(int32_t color) {
    std::unordered_map<LightColor, int32_t> intensities;
    intensities.emplace(LightColor::RED, getRed(color));
    intensities.emplace(LightColor::GREEN, getGreen(color));
    intensities.emplace(LightColor::BLUE, getBlue(color));

    context.setLightIntensities(rawId, intensities);
    setRawLightBrightness(rawId, getAlpha(color));
    return true;
}

std::optional<int32_t> PeripheralController::MonoLight::getLightColor() {
    std::optional<int32_t> brightness = getRawLightBrightness(rawId);
    if (!brightness.has_value()) {
        return std::nullopt;
    }

    return toArgb(brightness.value(), 0 /* red */, 0 /* green */, 0 /* blue */);
}

std::optional<int32_t> PeripheralController::RgbLight::getLightColor() {
    // If the Alpha component is zero, then return color 0.
    if (brightness == 0) {
        return 0;
    }
    // Compose color value as per:
    // https://developer.android.com/reference/android/graphics/Color?hl=en
    // int color = (A & 0xff) << 24 | (R & 0xff) << 16 | (G & 0xff) << 8 | (B & 0xff);
    std::optional<int32_t> redOr = getRawLightBrightness(rawRgbIds.at(LightColor::RED));
    std::optional<int32_t> greenOr = getRawLightBrightness(rawRgbIds.at(LightColor::GREEN));
    std::optional<int32_t> blueOr = getRawLightBrightness(rawRgbIds.at(LightColor::BLUE));
    // If we can't get brightness for any of the RGB light
    if (!redOr.has_value() || !greenOr.has_value() || !blueOr.has_value()) {
        return std::nullopt;
    }

    // Compose the ARGB format color. As the R,G,B color led brightness is scaled by Alpha
    // value, scale it back to return the nominal color value.
    float ratio = MAX_BRIGHTNESS / brightness;
    int32_t red = round(redOr.value() * ratio);
    int32_t green = round(greenOr.value() * ratio);
    int32_t blue = round(blueOr.value() * ratio);

    if (red > MAX_BRIGHTNESS || green > MAX_BRIGHTNESS || blue > MAX_BRIGHTNESS) {
        // Previously stored brightness isn't valid for current LED values, so just reset to max
        // brightness since an app couldn't have provided these values in the first place.
        red = redOr.value();
        green = greenOr.value();
        blue = blueOr.value();
        brightness = MAX_BRIGHTNESS;
    }

    return toArgb(brightness, red, green, blue);
}

std::optional<int32_t> PeripheralController::MultiColorLight::getLightColor() {
    auto ret = context.getLightIntensities(rawId);
    if (!ret.has_value()) {
        return std::nullopt;
    }
    std::unordered_map<LightColor, int32_t> intensities = ret.value();
    // Get red, green, blue colors
    int32_t color = toArgb(0 /* brightness */, intensities.at(LightColor::RED) /* red */,
                           intensities.at(LightColor::GREEN) /* green */,
                           intensities.at(LightColor::BLUE) /* blue */);
    // Get brightness
    std::optional<int32_t> brightness = getRawLightBrightness(rawId);
    if (brightness.has_value()) {
        return toArgb(brightness.value() /* A */, 0, 0, 0) | color;
    }
    return std::nullopt;
}

bool PeripheralController::PlayerIdLight::setLightPlayerId(int32_t playerId) {
    if (rawLightIds.find(playerId) == rawLightIds.end()) {
        return false;
    }
    for (const auto& [id, rawId] : rawLightIds) {
        if (playerId == id) {
            setRawLightBrightness(rawId, MAX_BRIGHTNESS);
        } else {
            setRawLightBrightness(rawId, 0);
        }
    }
    return true;
}

std::optional<int32_t> PeripheralController::PlayerIdLight::getLightPlayerId() {
    for (const auto& [id, rawId] : rawLightIds) {
        std::optional<int32_t> brightness = getRawLightBrightness(rawId);
        if (brightness.has_value() && brightness.value() > 0) {
            return id;
        }
    }
    return std::nullopt;
}

void PeripheralController::MonoLight::dump(std::string& dump) {
    dump += StringPrintf(INDENT4 "Color: 0x%x\n", getLightColor().value_or(0));
}

void PeripheralController::PlayerIdLight::dump(std::string& dump) {
    dump += StringPrintf(INDENT4 "PlayerId: %d\n", getLightPlayerId().value_or(-1));
    dump += StringPrintf(INDENT4 "Raw Player ID LEDs:");
    for (const auto& [id, rawId] : rawLightIds) {
        dump += StringPrintf("id %d -> %d ", id, rawId);
    }
    dump += "\n";
}

void PeripheralController::RgbLight::dump(std::string& dump) {
    dump += StringPrintf(INDENT4 "Color: 0x%x\n", getLightColor().value_or(0));
    dump += StringPrintf(INDENT4 "Raw RGB LEDs: [%d, %d, %d] ", rawRgbIds.at(LightColor::RED),
                         rawRgbIds.at(LightColor::GREEN), rawRgbIds.at(LightColor::BLUE));
    if (rawGlobalId.has_value()) {
        dump += StringPrintf(INDENT4 "Raw Global LED: [%d] ", rawGlobalId.value());
    }
    dump += "\n";
}

void PeripheralController::MultiColorLight::dump(std::string& dump) {
    dump += StringPrintf(INDENT4 "Color: 0x%x\n", getLightColor().value_or(0));
}

void PeripheralController::populateDeviceInfo(InputDeviceInfo* deviceInfo) {
    // TODO: b/180733860 Remove this after enabling multi-battery
    if (!mBatteries.empty()) {
        deviceInfo->setHasBattery(true);
    }

    for (const auto& [batteryId, battery] : mBatteries) {
        InputDeviceBatteryInfo batteryInfo(battery->name, battery->id);
        deviceInfo->addBatteryInfo(batteryInfo);
    }

    for (const auto& [lightId, light] : mLights) {
        // Input device light doesn't support ordinal, always pass 1.
        InputDeviceLightInfo lightInfo(light->name, light->id, light->type, 1 /* ordinal */);
        deviceInfo->addLightInfo(lightInfo);
    }
}

void PeripheralController::dump(std::string& dump) {
    dump += INDENT2 "Input Controller:\n";
    if (!mLights.empty()) {
        dump += INDENT3 "Lights:\n";
        for (const auto& [lightId, light] : mLights) {
            dump += StringPrintf(INDENT4 "Id: %d", lightId);
            dump += StringPrintf(INDENT4 "Name: %s", light->name.c_str());
            dump += StringPrintf(INDENT4 "Type: %s", ftl::enum_string(light->type).c_str());
            light->dump(dump);
        }
    }
    // Dump raw lights
    dump += INDENT3 "RawLights:\n";
    dump += INDENT4 "Id:\t Name:\t Flags:\t Max brightness:\t Brightness\n";
    const std::vector<int32_t> rawLightIds = getDeviceContext().getRawLightIds();
    // Map from raw light id to raw light info
    std::unordered_map<int32_t, RawLightInfo> rawInfos;
    for (const auto& rawId : rawLightIds) {
        std::optional<RawLightInfo> rawInfo = getDeviceContext().getRawLightInfo(rawId);
        if (!rawInfo.has_value()) {
            continue;
        }
        dump += StringPrintf(INDENT4 "%d", rawId);
        dump += StringPrintf(INDENT4 "%s", rawInfo->name.c_str());
        dump += StringPrintf(INDENT4 "%s", rawInfo->flags.string().c_str());
        dump += StringPrintf(INDENT4 "%d", rawInfo->maxBrightness.value_or(MAX_BRIGHTNESS));
        dump += StringPrintf(INDENT4 "%d\n",
                             getDeviceContext().getLightBrightness(rawId).value_or(-1));
    }

    if (!mBatteries.empty()) {
        dump += INDENT3 "Batteries:\n";
        for (const auto& [batteryId, battery] : mBatteries) {
            dump += StringPrintf(INDENT4 "Id: %d", batteryId);
            dump += StringPrintf(INDENT4 "Name: %s", battery->name.c_str());
            dump += getBatteryCapacity(batteryId).has_value()
                    ? StringPrintf(INDENT3 "Capacity: %d\n", getBatteryCapacity(batteryId).value())
                    : StringPrintf(INDENT3 "Capacity: Unknown");

            std::string status;
            switch (getBatteryStatus(batteryId).value_or(BATTERY_STATUS_UNKNOWN)) {
                case BATTERY_STATUS_CHARGING:
                    status = "Charging";
                    break;
                case BATTERY_STATUS_DISCHARGING:
                    status = "Discharging";
                    break;
                case BATTERY_STATUS_NOT_CHARGING:
                    status = "Not charging";
                    break;
                case BATTERY_STATUS_FULL:
                    status = "Full";
                    break;
                default:
                    status = "Unknown";
            }
            dump += StringPrintf(INDENT3 "Status: %s\n", status.c_str());
        }
    }
}

void PeripheralController::configureBattries() {
    // Check raw batteries
    const std::vector<int32_t> rawBatteryIds = getDeviceContext().getRawBatteryIds();

    for (const auto& rawId : rawBatteryIds) {
        std::optional<RawBatteryInfo> rawInfo = getDeviceContext().getRawBatteryInfo(rawId);
        if (!rawInfo.has_value()) {
            continue;
        }
        std::unique_ptr<Battery> battery =
                std::make_unique<Battery>(getDeviceContext(), rawInfo->name, rawInfo->id);
        mBatteries.insert_or_assign(rawId, std::move(battery));
    }
}

void PeripheralController::configureLights() {
    bool hasRedLed = false;
    bool hasGreenLed = false;
    bool hasBlueLed = false;
    std::optional<int32_t> rawGlobalId = std::nullopt;
    // Player ID light common name string
    std::string playerIdName;
    // Raw RGB color to raw light ID
    std::unordered_map<LightColor, int32_t /* rawLightId */> rawRgbIds;
    // Map from player Id to raw light Id
    std::unordered_map<int32_t, int32_t> playerIdLightIds;

    // Check raw lights
    const std::vector<int32_t> rawLightIds = getDeviceContext().getRawLightIds();
    // Map from raw light id to raw light info
    std::unordered_map<int32_t, RawLightInfo> rawInfos;
    for (const auto& rawId : rawLightIds) {
        std::optional<RawLightInfo> rawInfo = getDeviceContext().getRawLightInfo(rawId);
        if (!rawInfo.has_value()) {
            continue;
        }
        rawInfos.insert_or_assign(rawId, rawInfo.value());
        // Check if this is a group LEDs for player ID
        std::regex lightPattern("([a-z]+)([0-9]+)");
        std::smatch results;
        if (std::regex_match(rawInfo->name, results, lightPattern)) {
            std::string commonName = results[1].str();
            int32_t playerId = std::stoi(results[2]);
            if (playerIdLightIds.empty()) {
                playerIdName = commonName;
                playerIdLightIds.insert_or_assign(playerId, rawId);
            } else {
                // Make sure the player ID leds have common string name
                if (playerIdName.compare(commonName) == 0 &&
                    playerIdLightIds.find(playerId) == playerIdLightIds.end()) {
                    playerIdLightIds.insert_or_assign(playerId, rawId);
                }
            }
        }
        // Check if this is an LED of RGB light
        if (rawInfo->flags.test(InputLightClass::RED)) {
            hasRedLed = true;
            rawRgbIds.emplace(LightColor::RED, rawId);
        }
        if (rawInfo->flags.test(InputLightClass::GREEN)) {
            hasGreenLed = true;
            rawRgbIds.emplace(LightColor::GREEN, rawId);
        }
        if (rawInfo->flags.test(InputLightClass::BLUE)) {
            hasBlueLed = true;
            rawRgbIds.emplace(LightColor::BLUE, rawId);
        }
        if (rawInfo->flags.test(InputLightClass::GLOBAL)) {
            rawGlobalId = rawId;
        }
        if (DEBUG_LIGHT_DETAILS) {
            ALOGD("Light rawId %d name %s max %d flags %s \n", rawInfo->id, rawInfo->name.c_str(),
                  rawInfo->maxBrightness.value_or(MAX_BRIGHTNESS), rawInfo->flags.string().c_str());
        }
    }

    // Construct a player ID light
    if (playerIdLightIds.size() > 1) {
        std::unique_ptr<Light> light =
                std::make_unique<PlayerIdLight>(getDeviceContext(), playerIdName, ++mNextId,
                                                playerIdLightIds);
        mLights.insert_or_assign(light->id, std::move(light));
        // Remove these raw lights from raw light info as they've been used to compose a
        // Player ID light, so we do not expose these raw lights as mono lights.
        for (const auto& [playerId, rawId] : playerIdLightIds) {
            rawInfos.erase(rawId);
        }
    }
    // Construct a RGB light for composed RGB light
    if (hasRedLed && hasGreenLed && hasBlueLed) {
        if (DEBUG_LIGHT_DETAILS) {
            ALOGD("Rgb light ids [%d, %d, %d] \n", rawRgbIds.at(LightColor::RED),
                  rawRgbIds.at(LightColor::GREEN), rawRgbIds.at(LightColor::BLUE));
        }
        std::unique_ptr<Light> light =
                std::make_unique<RgbLight>(getDeviceContext(), ++mNextId, rawRgbIds, rawGlobalId);
        mLights.insert_or_assign(light->id, std::move(light));
        // Remove from raw light info as they've been composed a RBG light.
        rawInfos.erase(rawRgbIds.at(LightColor::RED));
        rawInfos.erase(rawRgbIds.at(LightColor::GREEN));
        rawInfos.erase(rawRgbIds.at(LightColor::BLUE));
        if (rawGlobalId.has_value()) {
            rawInfos.erase(rawGlobalId.value());
        }
    }

    // Check the rest of raw light infos
    for (const auto& [rawId, rawInfo] : rawInfos) {
        // If the node is multi-color led, construct a MULTI_COLOR light
        if (rawInfo.flags.test(InputLightClass::MULTI_INDEX) &&
            rawInfo.flags.test(InputLightClass::MULTI_INTENSITY)) {
            if (DEBUG_LIGHT_DETAILS) {
                ALOGD("Multicolor light Id %d name %s \n", rawInfo.id, rawInfo.name.c_str());
            }
            std::unique_ptr<Light> light =
                    std::make_unique<MultiColorLight>(getDeviceContext(), rawInfo.name, ++mNextId,
                                                      rawInfo.id);
            mLights.insert_or_assign(light->id, std::move(light));
            continue;
        }
        // Construct a Mono LED light
        if (DEBUG_LIGHT_DETAILS) {
            ALOGD("Mono light Id %d name %s \n", rawInfo.id, rawInfo.name.c_str());
        }
        std::unique_ptr<Light> light = std::make_unique<MonoLight>(getDeviceContext(), rawInfo.name,
                                                                   ++mNextId, rawInfo.id);

        mLights.insert_or_assign(light->id, std::move(light));
    }
}

std::optional<int32_t> PeripheralController::getBatteryCapacity(int batteryId) {
    return getDeviceContext().getBatteryCapacity(batteryId);
}

std::optional<int32_t> PeripheralController::getBatteryStatus(int batteryId) {
    return getDeviceContext().getBatteryStatus(batteryId);
}

bool PeripheralController::setLightColor(int32_t lightId, int32_t color) {
    auto it = mLights.find(lightId);
    if (it == mLights.end()) {
        return false;
    }
    auto& light = it->second;
    if (DEBUG_LIGHT_DETAILS) {
        ALOGD("setLightColor lightId %d type %s color 0x%x", lightId,
              ftl::enum_string(light->type).c_str(), color);
    }
    return light->setLightColor(color);
}

std::optional<int32_t> PeripheralController::getLightColor(int32_t lightId) {
    auto it = mLights.find(lightId);
    if (it == mLights.end()) {
        return std::nullopt;
    }
    auto& light = it->second;
    std::optional<int32_t> color = light->getLightColor();
    if (DEBUG_LIGHT_DETAILS) {
        ALOGD("getLightColor lightId %d type %s color 0x%x", lightId,
              ftl::enum_string(light->type).c_str(), color.value_or(0));
    }
    return color;
}

bool PeripheralController::setLightPlayerId(int32_t lightId, int32_t playerId) {
    auto it = mLights.find(lightId);
    if (it == mLights.end()) {
        return false;
    }
    auto& light = it->second;
    return light->setLightPlayerId(playerId);
}

std::optional<int32_t> PeripheralController::getLightPlayerId(int32_t lightId) {
    auto it = mLights.find(lightId);
    if (it == mLights.end()) {
        return std::nullopt;
    }
    auto& light = it->second;
    return light->getLightPlayerId();
}

int32_t PeripheralController::getEventHubId() const {
    return getDeviceContext().getEventHubId();
}

} // namespace android
