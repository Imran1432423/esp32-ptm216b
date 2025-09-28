/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <mutex>

#include <driver/gpio.h>

#include "constants.hpp"

namespace relay {

class relay
{
  public:
    static relay &get_instance() noexcept
    {
        static relay instance{};
        return instance;
    }

    static void toggle()
    {
        auto &i = get_instance();
        const std::lock_guard lock(i.m);
        i.status = !i.status;
        gpio_set_level(config::relay_gpio, i.status);
    }

    static void off()
    {
        auto &i = get_instance();
        const std::lock_guard lock(i.m);
        if (i.status != false) {
            i.status = false;
            gpio_set_level(config::relay_gpio, i.status);
        }
    }

    static void on()
    {
        auto &i = get_instance();
        const std::lock_guard lock(i.m);
        if (i.status != true) {
            i.status = true;
            gpio_set_level(config::relay_gpio, i.status);
        }
    }

    ~relay() = default;
    relay(const relay &other) = delete;
    relay &operator=(const relay &other) = delete;
    relay(relay &&other) = delete;
    relay &operator=(relay &&other) = delete;

  private:
    bool status{ false };
    std::mutex m;

    relay() noexcept
    {
        ESP_ERROR_CHECK(gpio_reset_pin(config::relay_gpio));
        ESP_ERROR_CHECK(gpio_set_direction(config::relay_gpio, GPIO_MODE_OUTPUT));
        ESP_ERROR_CHECK(gpio_set_level(config::relay_gpio, 0));
    }
};

};
