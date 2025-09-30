/*
 * SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>

#include <sdkconfig.h>

#include <driver/gpio.h>

#ifdef CONFIG_PTM216B_RELAY_GPIO
#define PTM216B_RELAY_GPIO CONFIG_PTM216B_RELAY_GPIO
#else
#define PTM216B_RELAY_GPIO 26
#endif

#ifdef CONFIG_PTM216B_LED_GPIO
#define PTM216B_LED_GPIO CONFIG_PTM216B_LED_GPIO
#else
#define PTM216B_LED_GPIO 19
#endif

#ifdef CONFIG_PTM216B_INT_BUTTON_GPIO
#define PTM216B_INT_BUTTON_GPIO CONFIG_PTM216B_INT_BUTTON_GPIO
#else
#define PTM216B_INT_BUTTON_GPIO 0
#endif

#ifdef CONFIG_PTM216B_S2_GPIO
#define PTM216B_S2_GPIO CONFIG_PTM216B_S2_GPIO
#else
#define PTM216B_S2_GPIO 27
#endif

#ifdef CONFIG_PTM216B_OTA
#define PTM216B_OTA true
#else
#define PTM216B_OTA false
#endif

#ifdef CONFIG_PTM216B_S_MODE_MONOSTABLE
#define PTM216B_S_MODE_MONOSTABLE true
#else
#define PTM216B_S_MODE_MONOSTABLE false
#endif

#ifdef CONFIG_PTM216B_GPIO_DEBOUNCE
#define PTM216B_GPIO_DEBOUNCE CONFIG_PTM216B_GPIO_DEBOUNCE
#else
#define PTM216B_GPIO_DEBOUNCE 10
#endif

#ifdef CONFIG_PTM216B_OTA_ON_INTERNAL_BUTTON
#define PTM216B_OTA_ON_INTERNAL_BUTTON true
#else
#define PTM216B_OTA_ON_INTERNAL_BUTTON false
#endif

#ifdef CONFIG_PTM216B_LED_ON
#define PTM216B_LED_STATUS 0
#else
#define PTM216B_LED_STATUS 1
#endif

#ifdef CONFIG_PTM216B_BRUTEFORCE_MITIGATION
#define PTM216B_BRUTEFORCE_MITIGATION true
#else
#define PTM216B_BRUTEFORCE_MITIGATION false
#endif

namespace config {
static const constexpr gpio_num_t relay_gpio = static_cast<gpio_num_t>(PTM216B_RELAY_GPIO);
static const constexpr gpio_num_t led_gpio = static_cast<gpio_num_t>(PTM216B_LED_GPIO);
static const constexpr gpio_num_t button_gpio =
        static_cast<gpio_num_t>(PTM216B_INT_BUTTON_GPIO);
static const constexpr gpio_num_t s2_gpio = static_cast<gpio_num_t>(PTM216B_S2_GPIO);
static const constexpr bool s2_monostable = PTM216B_S_MODE_MONOSTABLE;
static const constexpr bool ota_enable = PTM216B_OTA;
static const constexpr int gpio_debounce_delay = PTM216B_GPIO_DEBOUNCE;
static const constexpr bool ota_on_internal_button = PTM216B_OTA_ON_INTERNAL_BUTTON;
static const constexpr uint32_t led_status = PTM216B_LED_STATUS;
static const constexpr bool bruteforce_mitigation_enabled = PTM216B_BRUTEFORCE_MITIGATION;
};
