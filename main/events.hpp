/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

#include <esp_log.h>
#include <esp_timer.h>

#include "ota.hpp"
#include "ptm216b_fwd.hpp"
#include "relay.hpp"

namespace events {

namespace trigger_helpers {

[[maybe_unused]] static bool
exact_match(const std::vector<uint8_t> &raw, const std::vector<uint8_t> &value)
{
    return raw == value;
}

[[maybe_unused]] static bool
bitwise_and(const std::vector<uint8_t> &raw, const std::vector<uint8_t> &value)
{
    if (raw.size() > value.size())
        return false;
    for (size_t i = 0; i < raw.size(); ++i) {
        if ((raw[i] & value[i]) != raw[i])
            return false;
    }
    if (raw.size() == 1) {
        return (raw[0] & 0x1) == (value[0] & 0x1);
    }
    return true;
}

[[maybe_unused]] static bool
exact_match_timer(const std::vector<uint8_t> &raw,
                  const std::vector<uint8_t> &first,
                  const std::vector<uint8_t> &second,
                  const uint32_t duration)
{
    static std::mutex m;
    static std::map<std::vector<uint8_t>, int64_t> times;
    if (exact_match(raw, first)) {
        const auto time = esp_timer_get_time();
        const std::lock_guard lock(m);
        times.insert_or_assign(first, time);
    } else if (exact_match(raw, second)) {
        const auto time = esp_timer_get_time();
        const std::lock_guard lock(m);
        const auto tel = times.find(first);
        if (tel != times.end()) {
            const uint64_t diff = (time - tel->second) / 1000000;
            if (diff >= duration)
                return true;
        }
    }
    return false;
}

};

namespace actions {
using action_f = std::function<void(void)>;

[[maybe_unused]] static void
light_toggle()
{
    ESP_LOGI("actions", "light_toggle");
    relay::relay::toggle();
}

[[maybe_unused]] static void
light_off()
{
    ESP_LOGI("actions", "light_off");
    relay::relay::off();
}

[[maybe_unused]] static void
light_on()
{
    ESP_LOGI("actions", "light_on");
    relay::relay::on();
}

[[maybe_unused]] static void
ota() noexcept
{
    if (config::ota_enable) {
        ESP_LOGI("actions", "ota");
        if (ota::pending_verify()) {
            ESP_LOGI("actions", "FW verified");
            ota::verify_fw();
            return;
        }
        ota::ota_start();
    } else {
        ESP_LOGI("actions", "ota is disabled");
    }
}

};

};
